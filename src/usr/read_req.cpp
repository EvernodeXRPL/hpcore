#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../sc.hpp"
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
    std::thread read_req_thread;

    int init()
    {
        read_req_thread = std::thread(read_request_processor);
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;
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
                // Process the read requests by executing the contract.


                read_requests.clear();
            }
        }

        LOG_INFO << "Read request server stopped.";
    }

    void feed_requests_to_contract(std::unordered_map<std::string, std::list<std::string>> &read_requests)
    {
        sc::contract_bufmap_t user_iobufmap;
        sc::contract_iobuf_pair npl_bufpair;
        sc::contract_iobuf_pair hpsc_bufpair;

        // Populate read requests to user buf map.
        for (auto &[pubkey, requests] : read_requests)
        {
            sc::contract_iobuf_pair user_bufpair;
            user_bufpair.inputs.splice(user_bufpair.inputs.end(), requests);

            user_iobufmap.try_emplace(pubkey, std::move(user_bufpair));
        }

        
    }

} // namespace read_req