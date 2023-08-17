#ifndef _HP_COMM_COMM_SERVER_
#define _HP_COMM_COMM_SERVER_

#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../corebill/corebill.hpp"
#include "../corebill/tracker.hpp"
#include "hpws.hpp"
#include "comm_session.hpp"

namespace comm
{
    constexpr uint64_t DEFAULT_MAX_MSG_SIZE = 5 * 1024 * 1024;
    constexpr uint64_t DEFAULT_MAX_CONNECTIONS = 99999;
    constexpr uint16_t MAX_INBOUND_HIGH_PRIO_BTACH = 2; // Maximum no. of incomning high priority messages to process at a time.

    template <typename T>
    class comm_server
    {
    protected:
        const uint64_t (&metric_thresholds)[5];
        const uint64_t max_msg_size;
        const uint64_t max_in_connections;
        const uint64_t max_in_connections_per_host;
        bool use_priority_queues = false; // Whether to activate inbound message high vs low priority-based processing.
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
        std::thread watchdog_thread;          // Connection watcher thread.
        std::thread message_processor_thread; // Message processor thread.

        void connection_watchdog()
        {
            util::mask_signal();

            while (!is_shutting_down)
            {
                bool operations_performed = false;

                if (apply_ban_updates() > 0)
                    operations_performed = true;

                // Accept any new incoming connection if available.
                if (check_for_new_connection() > 0)
                    operations_performed = true;

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
                    {
                        itr->init();
                        operations_performed = true;
                    }
                }

                // Cleanup any sessions that needs closure.
                for (auto itr = sessions.begin(); itr != sessions.end();)
                {
                    // Check whether the connection expired according to last activity time rules.
                    itr->check_last_activity_rules();

                    if (itr->state == SESSION_STATE::MUST_CLOSE)
                    {
                        itr->close();
                        operations_performed = true;
                    }

                    if (itr->state == SESSION_STATE::CLOSED)
                        itr = sessions.erase(itr);
                    else
                        ++itr;
                }

                // If no operations were performed wait for some time before next iteration.
                if (!operations_performed)
                    util::sleep(100);
            }

            // If we reach this point that means we are shutting down.

            // Close and erase all sessions.
            for (T &session : sessions)
                session.close();

            sessions.clear();

            LOG_INFO << name << " listener stopped.";
        }

        /**
         * Sends ip address bans/unbans to hpws.
         * @return 0 if no updates applied. 1 if any updates were applied.
         */
        int apply_ban_updates()
        {
            bool updates_applied = false;

            corebill::ban_update b;
            while (violation_tracker.ban_updates.try_dequeue(b))
            {
                in_addr ia4 = {};
                in6_addr ia6 = {};

                if (inet_pton((b.is_ipv4 ? AF_INET : AF_INET6), b.host.c_str(), (b.is_ipv4 ? (void *)&ia4 : (void *)&ia6)) == 1)
                {
                    const uint32_t *addr = b.is_ipv4 ? (uint32_t *)&ia4.s_addr : ia6.__in6_u.__u6_addr32;
                    if (b.is_ban)
                        hpws_server->ban_ip(addr, b.ttl_sec, b.is_ipv4);
                    else
                        hpws_server->unban_ip(addr, b.is_ipv4);

                    updates_applied = true;
                }
                else
                {
                    LOG_ERROR << "Invalid host " << b.host << " in ban update.";
                }
            }

            return updates_applied ? 1 : 0;
        }

        /**
         * Accepts new websocket client connections if available.
         * @return 0 if no new client was waiting. 1 if a client was accepted. 2 if client was found but not accepted.
         */
        int check_for_new_connection()
        {
            if (listen_port == 0)
                return 0;

            std::variant<hpws::client, hpws::error> accept_result = hpws_server->accept(true);

            if (std::holds_alternative<hpws::error>(accept_result))
            {
                const hpws::error error = std::get<hpws::error>(accept_result);
                if (error.first == 199) // No client connected.
                    return 0;

                LOG_ERROR << "Error in hpws accept():" << error.first << " " << error.second;
                return 2;
            }

            // New client connected.
            hpws::client client = std::move(std::get<hpws::client>(accept_result));
            const std::variant<std::string, hpws::error> host_result = client.host_address();
            if (std::holds_alternative<hpws::error>(host_result))
            {
                const hpws::error error = std::get<hpws::error>(host_result);
                LOG_ERROR << "Error getting " << name << " ip from hpws:" << error.first << " " << error.second;
                return 2;
            }
            else
            {
                const std::string &host_address = std::get<std::string>(host_result);

                // We do not directly add to sessions list. We simply add to new_sessions list under a lock so the main server
                // loop will take care of initialize the new sessions. This is because inherited classes (eg. peer_comm_server)
                // need a way to safely inject new sessions from another thread.
                std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                new_sessions.emplace_back(this->violation_tracker, host_address, std::move(client), client.is_ipv4, true, metric_thresholds);
                return 1;
            }

            // If the hpws client object was not added to a session so far, in will get dstructed and the channel will close.
        }

        void message_processor_loop()
        {
            util::mask_signal();

            while (!is_shutting_down)
            {
                bool messages_processed = false;

                if (process_custom_messages() != 0)
                    messages_processed = true;

                {
                    std::scoped_lock<std::mutex> lock(sessions_mutex);

                    if (use_priority_queues)
                    {
                        // Process high priority messages from each session in round-robin fashion.
                        for (T &session : sessions)
                        {
                            // Process predefined no. of high priority messages from each session.

                            uint16_t high_prio_msgs_processed = 0; // High priority messages so far processed from this session.
                            int result = 0;
                            while (high_prio_msgs_processed < MAX_INBOUND_HIGH_PRIO_BTACH && // Check if we have reached the batch limit.
                                   (result = session.process_next_inbound_message(1)) != 0)
                            {
                                high_prio_msgs_processed++;
                                messages_processed = true;

                                if (result == -1)
                                    session.mark_for_closure(CLOSE_VIOLATION::VIOLATION_MSG_READ);
                            }
                        }
                    }

                    // Process one low priority message from each session in round-robin fashion.
                    for (T &session : sessions)
                    {
                        const int result = session.process_next_inbound_message(2);

                        if (result != 0)
                            messages_processed = true;

                        if (result == -1)
                            session.mark_for_closure(CLOSE_VIOLATION::VIOLATION_MSG_READ);
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
                max_in_connections,
                max_in_connections_per_host,
                conf::ctx.tls_cert_file,
                conf::ctx.tls_key_file,
                name == "Peer",
                {},
                util::fork_detach);

            if (std::holds_alternative<hpws::error>(result))
            {
                const hpws::error e = std::get<hpws::error>(result);
                LOG_ERROR << name << " hpws server creation failed. " << e.first << " " << e.second << " Port: " << std::to_string(listen_port);
                return -1;
            }

            hpws_server.emplace(std::move(std::get<hpws::server>(result)));

            return 0;
        }

    public:
        corebill::tracker violation_tracker;

        comm_server(std::string_view name, const uint16_t port, const uint64_t (&metric_thresholds)[5], const uint64_t max_msg_size,
                    const uint64_t max_in_connections, const uint64_t max_in_connections_per_host, const bool use_priority_queues)
            : metric_thresholds(metric_thresholds),
              max_msg_size(max_msg_size > 0 ? max_msg_size : DEFAULT_MAX_MSG_SIZE),
              max_in_connections(max_in_connections > 0 ? max_in_connections : DEFAULT_MAX_CONNECTIONS),
              max_in_connections_per_host(max_in_connections_per_host > 0 ? max_in_connections_per_host : DEFAULT_MAX_CONNECTIONS),
              use_priority_queues(use_priority_queues),
              name(name),
              listen_port(port)
        {
        }

        int start()
        {
            if (listen_port > 0 && start_hpws_server() == -1)
                return -1;

            watchdog_thread = std::thread(&comm_server<T>::connection_watchdog, this);
            message_processor_thread = std::thread(&comm_server<T>::message_processor_loop, this);
            start_custom_jobs();

            return 0;
        }

        void stop()
        {
            is_shutting_down = true;

            stop_custom_jobs();

            watchdog_thread.join();
            hpws_server.reset();

            message_processor_thread.join();
        }
    };

} // namespace comm

#endif
