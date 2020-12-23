#include "../comm/comm_server.hpp"
#include "../util/util.hpp"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../ledger.hpp"
#include "../unl.hpp"
#include "peer_comm_server.hpp"
#include "peer_comm_session.hpp"
#include "self_node.hpp"

namespace p2p
{
    constexpr float WEAKLY_CONNECTED_THRESHOLD = 0.7;
    // Globally exposed weakly connected status variable.
    bool is_weakly_connected = false;

    peer_comm_server::peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[5],
                                       const uint64_t max_msg_size, std::vector<conf::peer_properties> &req_known_remotes)
        : comm::comm_server<peer_comm_session>("Peer", port, metric_thresholds, max_msg_size),
          req_known_remotes(req_known_remotes)
    {
    }

    void peer_comm_server::start_custom_jobs()
    {
        // known_peers_thread = std::thread(&peer_comm_server::peer_monitor_loop, this);
        peer_managing_thread = std::thread(&peer_comm_server::peer_managing_loop, this);
    }

    void peer_comm_server::stop_custom_jobs()
    {
        // known_peers_thread.join();
        peer_managing_thread.join();
    }

    int peer_comm_server::process_custom_messages()
    {
        return self::process_next_message();
    }

    void peer_comm_server::custom_connections()
    {
        if (custom_connection_invocations == 20 || custom_connection_invocations == -1)
        {
            maintain_known_connections();
            custom_connection_invocations = 0;
        }

        custom_connection_invocations++;
    }

    // void peer_comm_server::peer_monitor_loop()
    // {
    //     util::mask_signal();

    //     LOG_INFO << "Started peer monitor.";

    //     while (!is_shutting_down)
    //     {
    //         util::sleep(2000);
    //         maintain_known_connections();
    //     }

    //     LOG_INFO << "Stopped peer monitor.";
    // }

    void peer_comm_server::peer_managing_loop()
    {
        util::mask_signal();

        LOG_INFO << "Started peer managing thread.";

        int peer_managing_counter = 0;

        while (!is_shutting_down)
        {
            peer_managing_counter++;

            // Send available peer capacity if peermaxcons is configured.
            if (conf::cfg.mesh.max_connections != 0)
                p2p::send_available_capacity_announcement(p2p::get_available_capacity());

            // Start peer list request loop if dynamic peer discovery is enabled.
            if (conf::cfg.mesh.peer_discovery.enabled && known_remote_count > 0)
            {
                // If max known peer connection cap is reached then periodically request peer list from random known peer.
                // Otherwise frequently request peer list from a random known peer.
                // Peer discovery time interval can be configured in the config.
                if (conf::cfg.mesh.max_known_connections != 0 && known_remote_count == conf::cfg.mesh.max_known_connections)
                {
                    if (peer_managing_counter * 100 >= conf::cfg.mesh.peer_discovery.interval * 5)
                    {
                        p2p::send_peer_list_request();
                        peer_managing_counter = 0;
                    }
                }
                else if (peer_managing_counter * 100 >= conf::cfg.mesh.peer_discovery.interval)
                {
                    p2p::send_peer_list_request();
                    peer_managing_counter = 0;
                }
            }

            // Check connected status of the node and sends the announcment
            // about the consensus message forwarding requirement.
            detect_if_weakly_connected();

            util::sleep(100);
        }

        LOG_INFO << "Stopped peer managing thread.";
    }

    void peer_comm_server::maintain_known_connections()
    {
        // Find already connected known remote parties list.
        std::vector<conf::ip_port_prop> known_remotes;

        {
            std::scoped_lock<std::mutex> lock(sessions_mutex);
            for (const p2p::peer_comm_session &session : sessions)
            {
                if (session.state != comm::SESSION_STATE::CLOSED && session.known_ipport.has_value())
                    known_remotes.push_back(session.known_ipport.value());
            }
        }

        // Update global known remote count when new connections are made.
        known_remote_count = known_remotes.size();

        std::scoped_lock<std::mutex> lock(req_known_remotes_mutex);

        for (const auto &peer : req_known_remotes)
        {
            if (is_shutting_down)
                break;

            // Break if known peer cap is reached.
            if (conf::cfg.mesh.max_known_connections != 0 && known_remote_count == conf::cfg.mesh.max_known_connections)
                break;

            // Break if max peer connection cap is reached.
            if (conf::cfg.mesh.max_connections != 0 && known_remote_count == conf::cfg.mesh.max_connections)
                break;

            // Continue if the peer has no free slots.
            if (peer.available_capacity == 0)
                continue;

            // Check if we are already connected to this remote party.
            if (std::find(known_remotes.begin(), known_remotes.end(), peer.ip_port) != known_remotes.end())
                continue;

            std::string_view host = peer.ip_port.host_address;
            const uint16_t port = peer.ip_port.port;
            LOG_DEBUG << "Trying to connect " << host << ":" << std::to_string(port);

            std::variant<hpws::client, hpws::error> client_result = hpws::client::connect(conf::ctx.hpws_exe_path, max_msg_size, host, port, "/", {}, util::fork_detach);

            if (std::holds_alternative<hpws::error>(client_result))
            {
                const hpws::error error = std::get<hpws::error>(client_result);
                if (error.first != 202)
                    LOG_DEBUG << "Outbound connection hpws error:" << error.first << " " << error.second;
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
                    p2p::peer_comm_session session(host_address, std::move(client), false, metric_thresholds);

                    // Skip if this peer is banned due to corebill violations.
                    if (corebill::is_banned(host_address))
                    {
                        LOG_DEBUG << "Skipping peer " << host_address << " from connecting. This peer is banned.";
                        continue;
                    }

                    session.known_ipport.emplace(peer.ip_port);
                    known_remote_count++;

                    std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                    new_sessions.emplace_back(std::move(session));
                }
            }
        }
    }
    /**
     * Check whether the node is weakly connected or strongly connected in every 60 seconds.
    */
    void peer_comm_server::detect_if_weakly_connected()
    {
        if (connected_status_check_counter == 600)
        {
            // One is added to session list size to reflect the loop back connection.
            const bool current_state = (sessions.size() + 1) < (unl::count() * WEAKLY_CONNECTED_THRESHOLD);
            if (is_weakly_connected != current_state)
            {
                is_weakly_connected = !is_weakly_connected;
                send_peer_requirement_announcement(is_weakly_connected);
            }
            connected_status_check_counter = 0;
        }
        connected_status_check_counter++;
    }
} // namespace p2p