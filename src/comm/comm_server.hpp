#ifndef _HP_COMM_COMM_SERVER_
#define _HP_COMM_COMM_SERVER_

#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../bill/corebill.h"
#include "../hpws/hpws.hpp"
#include "comm_session.hpp"

namespace comm
{
    constexpr uint32_t DEFAULT_MAX_MSG_SIZE = 16 * 1024 * 1024;

    template <typename T>
    class comm_server
    {
    protected:
        const uint64_t (&metric_thresholds)[4];
        const uint64_t max_msg_size;
        bool is_shutting_down = false;
        std::list<T> sessions;
        std::list<T> new_sessions; // Sessions that haven't been initialized properly which are yet to be merge to "sessions" list.
        std::mutex sessions_mutex;
        std::mutex new_sessions_mutex;

        virtual void start_custom_jobs()
        {
        }

        virtual void stop_custom_jobs()
        {
        }

        virtual int process_custom_messages()
        {
            return 0;
        }

    private:
        const std::string name;
        const uint16_t listen_port;
        std::optional<hpws::server> hpws_server;
        std::thread watchdog_thread;                  // Connection watcher thread.
        std::thread inbound_message_processor_thread; // Incoming message processor thread.

        void connection_watchdog()
        {
            util::mask_signal();

            while (!is_shutting_down)
            {
                util::sleep(100);

                // Accept any new incoming connection if available.
                check_for_new_connection();

                std::scoped_lock<std::mutex> lock(sessions_mutex);

                // Initialize any new sessions.
                {
                    // Get current last session.
                    auto ex_last_session = std::prev(sessions.end());

                    {
                        // Move new sessions to the end of "sessions" list.
                        std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                        sessions.splice(sessions.end(), new_sessions);
                    }

                    // Initialize newly inserted sessions.
                    // This must be performed after session objects end up in their final location.
                    for (auto itr = ++ex_last_session; itr != sessions.end(); itr++)
                        itr->init();
                }

                // Cleanup any sessions that needs closure.
                for (auto itr = sessions.begin(); itr != sessions.end();)
                {
                    if (itr->state == SESSION_STATE::MUST_CLOSE)
                        itr->close(true);

                    if (itr->state == SESSION_STATE::CLOSED)
                        itr = sessions.erase(itr);
                    else
                        ++itr;
                }
            }

            // If we reach this point that means we are shutting down.

            // Close and erase all sessions.
            for (T &session : sessions)
                session.close(false);

            sessions.clear();

            LOG_INFO << name << " listener stopped.";
        }

        void check_for_new_connection()
        {
            std::variant<hpws::client, hpws::error> accept_result = hpws_server.value().accept(true);

            if (std::holds_alternative<hpws::error>(accept_result))
            {
                const hpws::error error = std::get<hpws::error>(accept_result);
                if (error.first == 199) // No client connected.
                    return;

                LOG_ERROR << "Error in hpws accept():" << error.first << " " << error.second;
                return;
            }

            // New client connected.
            hpws::client client = std::move(std::get<hpws::client>(accept_result));
            const std::variant<std::string, hpws::error> host_result = client.host_address();
            if (std::holds_alternative<hpws::error>(host_result))
            {
                const hpws::error error = std::get<hpws::error>(host_result);
                LOG_ERROR << "Error getting " << name << " ip from hpws:" << error.first << " " << error.second;
            }
            else
            {
                const std::string &host_address = std::get<std::string>(host_result);
                if (!corebill::is_banned(host_address))
                {
                    // We do not directly add to sessions list. We simply add to new_sessions list under a lock so the main server
                    // loop will take care of initialize the new sessions. This is because inherited classes (eg. peer_comm_server)
                    // need a way to safely inject new sessions from another thread.
                    std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                    new_sessions.emplace_back(host_address, std::move(client), true, metric_thresholds);
                }
                else
                {
                    LOG_DEBUG << "Dropping " << name << " connection for banned host " << host_address;
                }
            }

            // If the hpws client object was not added to a session so far, in will get dstructed and the channel will close.
        }

        void inbound_message_processor_loop()
        {
            util::mask_signal();

            while (!is_shutting_down)
            {
                bool messages_processed = false;

                if (process_custom_messages() != 0)
                    messages_processed = true;

                {
                    // Process one message from each session in round-robin fashion.
                    std::scoped_lock<std::mutex> lock(sessions_mutex);
                    for (T &session : sessions)
                    {
                        const int result = session.process_next_inbound_message();

                        if (result != 0)
                            messages_processed = true;

                        if (result == -1)
                            session.mark_for_closure();
                    }
                }

                // If no messages were processed in this cycle, wait for some time.
                if (!messages_processed)
                    util::sleep(10);
            }

            LOG_INFO << name << " message processor stopped.";
        }

        int start_hpws_server()
        {
            std::variant<hpws::server, hpws::error> result = hpws::server::create(
                conf::ctx.hpws_exe_path,
                max_msg_size,
                listen_port,
                512, // Max connections
                2,   // Max connections per IP.
                conf::ctx.tls_cert_file,
                conf::ctx.tls_key_file,
                {},
                util::fork_detach);

            if (std::holds_alternative<hpws::error>(result))
            {
                const hpws::error e = std::get<hpws::error>(result);
                LOG_ERROR << "Error creating hpws server:" << e.first << " " << e.second;
                return -1;
            }

            hpws_server.emplace(std::move(std::get<hpws::server>(result)));

            return 0;
        }

    public:
        comm_server(std::string_view name, const uint16_t port, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size)
            : name(name),
              listen_port(port),
              metric_thresholds(metric_thresholds),
              max_msg_size(max_msg_size > 0 ? max_msg_size : DEFAULT_MAX_MSG_SIZE)
        {
        }

        int start()
        {
            if (start_hpws_server() == -1)
                return -1;

            watchdog_thread = std::thread(&comm_server<T>::connection_watchdog, this);
            inbound_message_processor_thread = std::thread(&comm_server<T>::inbound_message_processor_loop, this);
            start_custom_jobs();

            return 0;
        }

        void stop()
        {
            is_shutting_down = true;

            stop_custom_jobs();

            watchdog_thread.join();
            hpws_server.reset();

            inbound_message_processor_thread.join();
        }
    };

} // namespace comm

#endif
