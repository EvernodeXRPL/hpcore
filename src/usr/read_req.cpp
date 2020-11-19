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
    std::thread thread_pool_executor; // Thread which spawns new threads for the read requests is the queue.
    std::vector<std::thread> read_req_threads;
    moodycamel::ConcurrentQueue<user_read_req> read_req_queue(MAX_QUEUE_SIZE);
    std::mutex execution_contexts_mutex;
    std::list<sc::execution_context> execution_contexts;
    std::mutex completed_threads_mutex;
    std::vector<pthread_t> completed_threads;

    int init()
    {
        thread_pool_executor = std::thread(manage_thread_pool);
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            is_shutting_down = true;

            // Joining thread pool executor.
            thread_pool_executor.join();

            {
                // Force stoping all running contracts.
                std::scoped_lock<std::mutex> lock(execution_contexts_mutex);
                for (sc::execution_context &execution_context : execution_contexts)
                    sc::stop(execution_context);
            }

            // Joining all read request processing threads.
            for (std::thread &thread : read_req_threads)
                thread.join();
        }
    }

    /**
     * Processing read requests via multiple threads by checking for maximum thread cap and read request availability.
    */
    void manage_thread_pool()
    {
        LOG_INFO << "Read request thread pool manager started.";
        util::mask_signal();

        while (!is_shutting_down)
        {
            // Cleanup any exited threads.
            {
                std::scoped_lock<std::mutex> lock(completed_threads_mutex);
                if (!completed_threads.empty())
                {
                    // Remove all the completed threads from the read_req_threads list.
                    for (const pthread_t thread_id : completed_threads)
                    {
                        // Remove thread with the given completed thread id from the read_req_threads list.
                        remove_thread(thread_id);
                    }

                    LOG_DEBUG << completed_threads.size() << " threads cleaned from read requests thread pool.";

                    // Clear the completed thread id list once the completed threads are removed from the list.
                    completed_threads.clear();
                }
            }

            if (read_req_queue.size_approx() != 0 && read_req_threads.size() <= MAX_THREAD_CAP)
            {
                read_req_threads.push_back(std::thread(read_request_processor));
                if (read_req_queue.size_approx() == 1)
                {
                    // The sleep is added to avoid creating a new thread before the newly created thread dequeue the job
                    // from the queue.
                    util::sleep(10);
                }
            }
            else
            {
                util::sleep(LOOP_WAIT);
            }
        }
        LOG_INFO << "Read request thread pool manager ended.";
    }

    /**
     * Process read requests from read request queue and execute smart contract.
     * Process all the available read requests and exits if the queue is empty.
    */
    void read_request_processor()
    {
        LOG_DEBUG << "A new read request processing thread started.";

        util::mask_signal();

        std::list<sc::execution_context>::iterator context_itr;

        // Own pthread id.
        const pthread_t thread_id = pthread_self();

        while (!is_shutting_down)
        {
            user_read_req read_request;
            if (read_req_queue.try_dequeue(read_request))
            {
                {
                    // Contract context is added to the list for force kill if a SIGINT is received.
                    sc::execution_context contract_ctx;
                    std::scoped_lock<std::mutex> execution_contract_lock(execution_contexts_mutex);
                    context_itr = execution_contexts.emplace(execution_contexts.begin(), std::move(contract_ctx));
                }

                // Populate execution context data if any read requests are available in the queue.
                initialize_execution_context(std::move(read_request), thread_id, *context_itr);
                LOG_DEBUG << "Read request contract execution started.";

                // Process the read requests by executing the contract.
                if (sc::execute_contract(*context_itr) != -1)
                {
                    // If contract execution was succcessful, send the output back to user.
                    std::scoped_lock<std::mutex> lock(usr::ctx.users_mutex);

                    const auto user_buf_itr = context_itr->args.userbufs.begin();
                    if (!user_buf_itr->second.outputs.empty())
                    {
                        // Find the user session by user pubkey.
                        const auto user_itr = usr::ctx.users.find(user_buf_itr->first);
                        if (user_itr != usr::ctx.users.end()) // match found
                        {
                            const usr::connected_user &user = user_itr->second;
                            msg::usrmsg::usrmsg_parser parser(user.protocol);
                            for (sc::contract_output &output : user_buf_itr->second.outputs)
                            {
                                std::vector<uint8_t> msg;
                                parser.create_contract_read_response_container(msg, output.message);
                                user.session.send(msg);
                                output.message.clear();
                            }
                            user_buf_itr->second.outputs.clear();
                        }
                    }
                    LOG_DEBUG << "Read request contract execution ended.";
                }
                else
                {
                    LOG_ERROR << "Contract execution for read request failed.";
                }

                // Remove successfully executed execution contexts.
                std::scoped_lock<std::mutex> execution_contract_lock(execution_contexts_mutex);
                execution_contexts.erase(context_itr);
            }
            else
            {
                LOG_DEBUG << "Thread exits, due to no more read requests.";
                // Break while loop if no read request is present in the queue for processing.
                break;
            }
        }

        // Add current thread id to to the list of completed threads.
        std::scoped_lock<std::mutex> lock(completed_threads_mutex);
        completed_threads.push_back(thread_id);

        LOG_DEBUG << "Read request processing thread exited.";
    }

    /**
     * Add new read request from users to the read request queue for processing.
     * @param pubkey Public key of the user.
     * @param content Message content.
     * @return 0 on successful addition and -1 on queue overflow
    */
    int populate_read_req_queue(const std::string &pubkey, const std::string &content)
    {
        user_read_req read_request;
        read_request.content = std::move(content);
        read_request.pubkey = pubkey;

        return read_req_queue.try_enqueue(read_request);
    }

    /**
     * Populate execution context data from the given read request.
     * @param read_request Received read request.
     * @param contract_ctx Execution context to be populated.
     * @param thread_id Id of the current thread. 
    */
    void initialize_execution_context(const user_read_req &read_request, const pthread_t thread_id, sc::execution_context &contract_ctx)
    {
        // Create new folder with the thread id per each thread.
        contract_ctx.args.state_dir = conf::ctx.state_dir;
        contract_ctx.args.state_dir.append("/rr_").append(std::to_string(thread_id));
        contract_ctx.args.readonly = true;
        sc::contract_iobufs user_bufs;
        user_bufs.inputs.push_back(std::move(read_request.content));
        contract_ctx.args.userbufs.try_emplace(read_request.pubkey, std::move(user_bufs));
    }

    /**
     * Join the thread with the given id and remove from the thread list.
     * @param id Id of the thread to be joined and removed.
    */
    void remove_thread(const pthread_t id)
    {
        const auto iter = std::find_if(read_req_threads.begin(), read_req_threads.end(), [=](std::thread &t) { return (t.native_handle() == id); });
        if (iter != read_req_threads.end())
        {
            iter->join();
            read_req_threads.erase(iter);
        }
    }

} // namespace read_req