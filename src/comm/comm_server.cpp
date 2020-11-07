#include "comm_server.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../bill/corebill.h"
#include "../hpws/hpws.hpp"
#include "../p2p/p2p.hpp"

namespace comm
{
    constexpr uint32_t DEFAULT_MAX_MSG_SIZE = 16 * 1024 * 1024;

    template <typename T>
    comm_server<T>::comm_server(std::string_view name, const uint16_t port, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size)
        : name(name),
          port(port),
          metric_thresholds(metric_thresholds),
          max_msg_size(max_msg_size > 0 ? max_msg_size : DEFAULT_MAX_MSG_SIZE)
    {
    }

    template <typename T>
    int comm_server<T>::start()
    {
        if (start_hpws_server() == -1)
            return -1;

        watchdog_thread = std::thread(&comm_server<T>::connection_watchdog, this);
        inbound_message_processor_thread = std::thread(&comm_server<T>::inbound_message_processor_loop, this);

        return 0;
    }

    template <typename T>
    void comm_server<T>::connection_watchdog()
    {
        util::mask_signal();

        // Counter to track when to initiate outbound client connections.
        int16_t loop_counter = -1;

        while (!should_stop_listening)
        {
            util::sleep(100);

            // Accept any new incoming connection if available.
            check_for_new_connection();

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

    template <typename T>
    void comm_server<T>::check_for_new_connection()
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

            if (corebill::is_banned(host_address))
            {
                // We just let the client object gets destructed without adding it to a session.
                LOG_DEBUG << "Dropping " << name << " connection for banned host " << host_address;
            }
            else
            {
                T session(host_address, std::move(client), session_type, true, metric_thresholds);
                if (session.on_connect() == 0)
                {
                    std::scoped_lock<std::mutex> lock(sessions_mutex);
                    T &inserted_session = sessions.emplace_back(std::move(session));

                    // Thread is seperately started after the moving operation to overcome the difficulty
                    // in accessing class member variables inside the thread.
                    // Class member variables gives unacceptable values if the thread starts before the move operation.
                    inserted_session.start_messaging_threads();
                }
            }
        }
    }

    template <typename T>
    void comm_server<T>::inbound_message_processor_loop()
    {
        util::mask_signal();

        while (!should_stop_listening)
        {
            bool messages_processed = false;

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

    template <typename T>
    int comm_server<T>::start_hpws_server()
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

    template <typename T>
    void comm_server<T>::stop()
    {
        should_stop_listening = true;
        watchdog_thread.join();
        hpws_server.reset();

        inbound_message_processor_thread.join();
    }

} // namespace comm
