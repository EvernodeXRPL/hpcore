#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "usr.hpp"
#include "read_req.hpp"

/**
 * Helper functions for serving read requests from users.
 */
namespace read_req
{
    constexpr uint16_t LOOP_WAIT = 100; // Milliseconds
    bool is_shutting_down = false;
    bool init_success = false;
    const int INITIAL_QUEUE_SIZE = 100;
    std::thread read_req_threads[5];
    moodycamel::ConcurrentQueue<user_read_req> read_req_queue(INITIAL_QUEUE_SIZE);

    int init()
    {
        for (std::thread &thread : read_req_threads)
            thread = std::thread(read_request_processor);
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;

            for (std::thread &thread : read_req_threads)
                thread.join();
        }
    }

    void read_request_processor()
    {
        util::mask_signal();

        sc::execution_context contract_ctx;
        while (!is_shutting_down)
        {

            if (initialize_contract(contract_ctx) != -1)
            {
                // Process the read requests by executing the contract.
                if (sc::execute_contract(contract_ctx) != -1)
                {
                    // If contract execution was succcessful, send the outputs back to users.
                    std::lock_guard<std::mutex> lock(usr::ctx.users_mutex);

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

                                    const usr::connected_user &user = user_itr->second;
                                    msg::usrmsg::usrmsg_parser parser(user.protocol);

                                    std::vector<uint8_t> msg;
                                    parser.create_contract_read_response_container(msg, outputtosend);

                                    user.session.send(msg);
                                }
                            }
                        }
                    }

                    sc::clear_args(contract_ctx.args);
                }
                else
                {
                    LOG_ERR << "Contract execution for read request failed.";
                }
            }
            else
            {
                // Queue is empty. Sleep for 10ms.
                util::sleep(LOOP_WAIT);
            }
        }

        LOG_INFO << "Read request server stopped.";
    }

    /**
     * Add new read request from users to the read request queue for processing.
     * @param pubkey Public key of the user.
     * @param content Message content.
     * @return 0 on successful addition and -1 on queue overflow
    */
    int populate_read_req_queue(const std::string &pubkey, const std::string &content)
    {
        sc::execution_context contract_ctx;

        user_read_req read_request;
        read_request.content = content;
        read_request.pubkey = pubkey;

        return read_req_queue.try_enqueue(read_request);
    }

    int initialize_contract(sc::execution_context &contract_ctx)
    {
        user_read_req read_request;
        if (read_req_queue.try_dequeue(read_request))
        {
            contract_ctx.args.state_dir = conf::ctx.state_read_req_dir;
            contract_ctx.args.readonly = true;
            sc::contract_iobuf_pair user_bufpair;
            std::list<std::string> input_list;
            input_list.push_back(std::move(read_request.content));
            user_bufpair.inputs.splice(user_bufpair.inputs.end(), input_list);
            contract_ctx.args.userbufs.try_emplace(read_request.pubkey, std::move(user_bufpair));
            return 0;
        }
        else
        {
            return -1;
        }
    }

} // namespace read_req