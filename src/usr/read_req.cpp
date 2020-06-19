#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../sc.hpp"
#include "../conf.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "usr.hpp"
#include "read_req.hpp"

namespace jusrmsg = jsonschema::usrmsg;

/**
 * Helper functions for serving read requests from users.
 */
namespace read_req
{
    constexpr uint16_t LOOP_WAIT = 100; // Milliseconds
    bool is_shutting_down = false;
    bool init_success = false;
    std::thread read_req_thread;
    sc::execution_context contract_ctx;

    int init()
    {
        contract_ctx.args.state_dir = conf::ctx.state_read_req_dir;
        contract_ctx.args.readonly = true;

        read_req_thread = std::thread(read_request_processor);
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;

            // Stop the contract if running.
            sc::stop(contract_ctx);

            read_req_thread.join();
        }
    }

    void read_request_processor()
    {
        util::mask_signal();

        LOG_INFO << "Read request server started.";

        // Lists of read requests submitted by users keyed by user pubkey.
        std::unordered_map<std::string, std::list<std::string>> read_requests;

        while (!is_shutting_down)
        {
            util::sleep(LOOP_WAIT);

            {
                std::lock_guard<std::mutex> lock(usr::ctx.users_mutex);

                // Move collected read requests from users over to local requests list.
                for (auto &[sid, user] : usr::ctx.users)
                {
                    if (!user.read_requests.empty())
                    {
                        std::list<std::string> user_read_requests;
                        user_read_requests.splice(user_read_requests.end(), user.read_requests);

                        read_requests.try_emplace(user.pubkey, std::move(user_read_requests));
                    }
                }
            }

            if (!read_requests.empty())
            {
                LOG_DBG << "Processing read requests... count:" << read_requests.size();

                // Process the read requests by executing the contract.
                if (execute_contract(read_requests) != -1)
                {
                    // If contract execution was succcessful, send the outputs back to users.
                    std::lock_guard<std::mutex> lock(usr::ctx.users_mutex);

                    uint32_t dispatch_count = 0;
                    for (auto &[pubkey, bufpair] : contract_ctx.args.userbufs)
                    {
                        if (!bufpair.output.empty())
                        {
                            // Find the user session by user pubkey.
                            const auto sess_itr = usr::ctx.sessionids.find(pubkey);
                            if (sess_itr != usr::ctx.sessionids.end()) // match found
                            {
                                const auto user_itr = usr::ctx.users.find(sess_itr->second); // sess_itr->second is the session id.
                                if (user_itr != usr::ctx.users.end())                        // match found
                                {
                                    std::string outputtosend;
                                    outputtosend.swap(bufpair.output);

                                    std::string msg;
                                    jusrmsg::create_contract_read_response_container(msg, outputtosend);

                                    const usr::connected_user &user = user_itr->second;
                                    user.session.send(msg);
                                    dispatch_count++;
                                }
                            }
                        }
                    }

                    sc::clear_args(contract_ctx.args);
                    LOG_DBG << "Dispatched read request responses. count:" << dispatch_count;
                }
                else
                {
                    LOG_ERR << "Contract execution for read requests failed.";
                }

                read_requests.clear();
            }
        }

        LOG_INFO << "Read request server stopped.";
    }

    int execute_contract(std::unordered_map<std::string, std::list<std::string>> &read_requests)
    {
        // Populate read requests to user buf map.
        for (auto &[pubkey, requests] : read_requests)
        {
            sc::contract_iobuf_pair user_bufpair;
            user_bufpair.inputs.splice(user_bufpair.inputs.end(), requests);

            contract_ctx.args.userbufs.try_emplace(pubkey, std::move(user_bufpair));
        }

        // Execute the contract.
        return sc::execute_contract(contract_ctx);
    }

} // namespace read_req