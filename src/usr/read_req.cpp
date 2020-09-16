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
    constexpr uint16_t LOOP_WAIT = 100;      // Milliseconds.
    constexpr uint16_t MAX_QUEUE_SIZE = 100; // Maximum read request queue size.
    constexpr uint16_t MAX_THREAD_CAP = 5;   // Maximum number of read request processing threads.

    bool is_shutting_down = false;
    bool init_success = false;
    std::thread thread_pool_executor;   // Thread which spawns new threads for the read requests is the queue.
    std::thread thread_pool_disposer;   // Thread which disposes execution completed threads.
    std::mutex thread_vector_mutex;
    std::vector<std::thread> read_req_threads;
    moodycamel::ConcurrentQueue<user_read_req> read_req_queue(MAX_QUEUE_SIZE);
    std::mutex execution_context_list_mutex;
    std::list<sc::execution_context> execution_context_list;
    std::mutex completed_thread_vector_mutex;
    std::vector<std::thread::id> completed_thread_ids;

    int init()
    {
        thread_pool_executor = std::thread(manage_thread_pool);
        thread_pool_disposer = std::thread(dispose_thread_pool);
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;

            // Force stoping all running contracts.
            for (sc::execution_context &execution_context : execution_context_list)
                sc::stop(execution_context);

            // Joining all read request processing threads.
            for (std::thread &thread : read_req_threads)
                thread.join();

            // Joining thread pool executor.
            thread_pool_executor.join();

            // Joining thread pool disposer.
            thread_pool_disposer.join();
        }
    }

    /**
     * Processing read requests via multiple threads by checking for maximum thread cap and read request availability.
    */
    void manage_thread_pool()
    {
        util::mask_signal();

        while (!is_shutting_down)
        {
            if (read_req_queue.size_approx() != 0 && read_req_threads.size() <= MAX_THREAD_CAP)
            {
                std::scoped_lock<std::mutex> lock(thread_vector_mutex);
                read_req_threads.push_back(std::thread(read_request_processor));
            }
            util::sleep(LOOP_WAIT);
        }
    }

    /**
     * Dispose threads if execution is completed.
    */
    void dispose_thread_pool()
    {
        util::mask_signal();

        while (!is_shutting_down)
        {
            {
                std::scoped_lock<std::mutex> lock(completed_thread_vector_mutex);
                if (!completed_thread_ids.empty())
                {
                    // Remove all the completed threads from the read_req_threads list.
                    for (std::thread::id thread_id : completed_thread_ids)
                    {
                        // Remove thread with the given completed thread id from the read_req_threads list.
                        remove_thread(thread_id);
                    }
                    // Clear the completed thread id list once the completed threads are removed from the list. 
                    completed_thread_ids.clear();
                }
            }
            util::sleep(LOOP_WAIT);
        }
    }

    /**
     * Process read requests from read request queue and execute smart contract.
     * Process all the available read requests and exits if the queue is empty.
    */
    void read_request_processor()
    {
        util::mask_signal();

        std::list<sc::execution_context>::iterator context_itr;

        while (!is_shutting_down)
        {
            {
                // Contract context is added to the list for force kill if a SIGINT is received.
                sc::execution_context contract_ctx;
                std::scoped_lock<std::mutex> execution_contract_lock(execution_context_list_mutex);
                context_itr = execution_context_list.emplace(execution_context_list.begin(), std::move(contract_ctx));
            }

            // Populate execution context data if any read requests are available in the queue.
            if (initialize_execution_context(*context_itr))
            {
                // Process the read requests by executing the contract.
                if (sc::execute_contract(*context_itr) != -1)
                {
                    // If contract execution was succcessful, send the outputs back to users.
                    std::lock_guard<std::mutex> lock(usr::ctx.users_mutex);

                    for (auto &[pubkey, bufpair] : context_itr->args.userbufs)
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
                    sc::clear_args(context_itr->args);
                }
                else
                {
                    LOG_ERR << "Contract execution for read request failed.";
                }
            }
            else
            {
                // Break while loop if no read request is precent in the queue for processing.
                break;
            }

            // Remove successfully executed execution contexts.
            std::scoped_lock<std::mutex> execution_contract_lock(execution_context_list_mutex);
            execution_context_list.erase(context_itr);
        }

        // Add current thread id to to the list of completed threads.
        std::scoped_lock<std::mutex> lock(completed_thread_vector_mutex);
        completed_thread_ids.push_back(std::this_thread::get_id());
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

    /**
     * Check the queue for a available read request and populate execution context data.
     * @param contract_ctx execution context to be populated.
     * @return return true if a read request is available for execution and false otherwise.  
    */
    bool initialize_execution_context(sc::execution_context &contract_ctx)
    {
        user_read_req read_request;
        if (read_req_queue.try_dequeue(read_request))
        {
            contract_ctx.args.state_dir = conf::ctx.state_read_req_dir;
            // Create new folder with the thread id per each thread.
            contract_ctx.args.state_dir.append("/").append(std::to_string(pthread_self()));
            contract_ctx.args.readonly = true;
            sc::contract_iobuf_pair user_bufpair;
            std::list<std::string> input_list;
            input_list.push_back(std::move(read_request.content));
            user_bufpair.inputs.splice(user_bufpair.inputs.end(), input_list);
            contract_ctx.args.userbufs.try_emplace(read_request.pubkey, std::move(user_bufpair));
            return true;
        }
        return false;
    }

    /**
     * Join the thread with the given id and remove from the thread list.
     * @param id Id of the thread to be joined and removed.
    */
    void remove_thread(std::thread::id id)
    {
        std::scoped_lock<std::mutex> lock(thread_vector_mutex);
        auto iter = std::find_if(read_req_threads.begin(), read_req_threads.end(), [=](std::thread &t) { return (t.get_id() == id); });
        if (iter != read_req_threads.end())
        {
            iter->join();
            read_req_threads.erase(iter);
        }
    }

} // namespace read_req