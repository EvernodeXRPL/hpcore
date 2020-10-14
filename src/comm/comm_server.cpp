#include "comm_server.hpp"
#include "comm_session.hpp"
#include "comm_session_handler.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../bill/corebill.h"
#include "../hpws/hpws.hpp"

namespace comm
{
    constexpr uint32_t DEFAULT_MAX_MSG_SIZE = 16 * 1024 * 1024;

    int comm_server::start(
        const uint16_t port, const SESSION_TYPE session_type, const uint64_t (&metric_thresholds)[4],
        const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size)
    {
        const uint64_t final_max_msg_size = max_msg_size > 0 ? max_msg_size : DEFAULT_MAX_MSG_SIZE;

        if (start_hpws_server(port, final_max_msg_size) == -1)
            return -1;

        watchdog_thread = std::thread(
            &comm_server::connection_watchdog, this, session_type,
            std::ref(metric_thresholds), req_known_remotes, final_max_msg_size);

        inbound_message_processor_thread = std::thread(&comm_server::inbound_message_processor_loop, this, session_type);

        return 0;
    }

    void comm_server::connection_watchdog(
        const SESSION_TYPE session_type, const uint64_t (&metric_thresholds)[4],
        const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size)
    {
        util::mask_signal();

        // Counter to track when to initiate outbound client connections.
        int16_t loop_counter = -1;

        while (!should_stop_listening)
        {
            util::sleep(100);

            // Accept any new incoming connection if available.
            check_for_new_connection(sessions, session_type, metric_thresholds);

            // Restore any missing outbound connections.
            if (!req_known_remotes.empty())
            {
                if (loop_counter == 20)
                {
                    loop_counter = 0;
                    maintain_known_connections(sessions, req_known_remotes, session_type, max_msg_size, metric_thresholds);
                }
                loop_counter++;
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
        for (comm_session &session : sessions)
            session.close(false);

        sessions.clear();

        LOG_INFO << (session_type == SESSION_TYPE::USER ? "User" : "Peer") << " listener stopped.";
    }

    void comm_server::check_for_new_connection(
        std::list<comm_session> &sessions, const SESSION_TYPE session_type, const uint64_t (&metric_thresholds)[4])
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
            LOG_ERROR << "Error getting ip from hpws:" << error.first << " " << error.second;
        }
        else
        {
            const std::string &host_address = std::get<std::string>(host_result);

            if (corebill::is_banned(host_address))
            {
                // We just let the client object gets destructed without adding it to a session.
                LOG_DEBUG << "Dropping connection for banned host " << host_address;
            }
            else
            {
                comm_session session(host_address, std::move(client), session_type, true, metric_thresholds);
                if (session.on_connect() == 0)
                {
                    std::scoped_lock<std::mutex> lock(sessions_mutex);
                    comm_session &inserted_session = sessions.emplace_back(std::move(session));

                    // Thread is seperately started after the moving operation to overcome the difficulty
                    // in accessing class member variables inside the thread.
                    // Class member variables gives unacceptable values if the thread starts before the move operation.
                    inserted_session.start_messaging_threads();
                }
            }
        }
    }

    void comm_server::maintain_known_connections(
        std::list<comm_session> &sessions, const std::set<conf::ip_port_pair> &req_known_remotes,
        const SESSION_TYPE session_type, const uint64_t max_msg_size, const uint64_t (&metric_thresholds)[4])
    {
        // Find already connected known remote parties list
        std::set<conf::ip_port_pair> known_remotes;
        for (const comm_session &session : sessions)
        {
            if (session.state != SESSION_STATE::CLOSED && !session.known_ipport.first.empty())
                known_remotes.emplace(session.known_ipport);
        }

        for (const auto &ipport : req_known_remotes)
        {
            if (should_stop_listening)
                break;

            // Check if we are already connected to this remote party.
            if (known_remotes.find(ipport) != known_remotes.end())
                continue;

            std::string_view host = ipport.first;
            const uint16_t port = ipport.second;
            LOG_DEBUG << "Trying to connect " << host << ":" << std::to_string(port);

            std::variant<hpws::client, hpws::error> client_result = hpws::client::connect(conf::ctx.hpws_exe_path, max_msg_size, host, port, "/", {}, util::fork_detach);

            if (std::holds_alternative<hpws::error>(client_result))
            {
                const hpws::error error = std::get<hpws::error>(client_result);
                LOG_ERROR << "Outbound connection hpws error:" << error.first << " " << error.second;
            }
            else
            {
                hpws::client client = std::move(std::get<hpws::client>(client_result));
                const std::variant<std::string, hpws::error> host_result = client.host_address();
                if (std::holds_alternative<hpws::error>(host_result))
                {
                    const hpws::error error = std::get<hpws::error>(host_result);
                    LOG_ERROR << "Error getting ip from hpws:" << error.first << " " << error.second;
                }
                else
                {
                    const std::string &host_address = std::get<std::string>(host_result);
                    comm::comm_session session(host_address, std::move(client), session_type, false, metric_thresholds);
                    session.known_ipport = ipport;
                    if (session.on_connect() == 0)
                    {
                        std::scoped_lock<std::mutex> lock(sessions_mutex);
                        comm_session &inserted_session = sessions.emplace_back(std::move(session));

                        // Thread is seperately started after the moving operation to overcome the difficulty
                        // in accessing class member variables inside the thread.
                        // Class member variables gives unacceptable values if the thread starts before the move operation.
                        inserted_session.start_messaging_threads();

                        known_remotes.emplace(ipport);
                    }
                }
            }
        }
    }

    void comm_server::inbound_message_processor_loop(const SESSION_TYPE session_type)
    {
        util::mask_signal();

        while (!should_stop_listening)
        {
            bool messages_processed = false;

            {
                // Process one message from each session in round-robin fashion.
                std::scoped_lock<std::mutex> lock(sessions_mutex);
                for (comm_session &session : sessions)
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

        LOG_INFO << (session_type == SESSION_TYPE::USER ? "User" : "Peer") << " message processor stopped.";
    }

    int comm_server::start_hpws_server(const uint16_t port, const uint64_t max_msg_size)
    {
        std::variant<hpws::server, hpws::error> result = hpws::server::create(
            conf::ctx.hpws_exe_path,
            max_msg_size,
            port,
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

    void comm_server::stop()
    {
        should_stop_listening = true;
        watchdog_thread.join();
        hpws_server.reset();

        inbound_message_processor_thread.join();
    }

} // namespace comm
