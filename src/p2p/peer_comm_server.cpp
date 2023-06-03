#include "../comm/comm_server.hpp"
#include "../util/util.hpp"
#include "../ledger/ledger.hpp"
#include "../unl.hpp"
#include "../conf.hpp"
#include "peer_comm_server.hpp"
#include "peer_comm_session.hpp"
#include "self_node.hpp"
#include "../status.hpp"

namespace p2p
{
    constexpr float WEAKLY_CONNECTED_THRESHOLD = 0.7;
    constexpr int16_t PEER_FAILED_THRESHOLD = 10;
    // Peer will be removed from the dead known peers collection after this period of time.
    constexpr int32_t DEAD_PEER_TIMEOUT = 5 * 60 * 1000; // 5 minutes.

    peer_comm_server::peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[5], const uint64_t max_msg_size,
                                       const uint64_t max_in_connections, const uint64_t max_in_connections_per_host,
                                       const std::vector<peer_properties> &req_known_remotes)
        : comm::comm_server<peer_comm_session>("Peer", port, metric_thresholds, max_msg_size, max_in_connections, max_in_connections_per_host, true),
          req_known_remotes(req_known_remotes) // Copy over known peers into internal collection.
    {
    }

    void peer_comm_server::start_custom_jobs()
    {
        peer_managing_thread = std::thread(&peer_comm_server::peer_managing_loop, this);
    }

    void peer_comm_server::stop_custom_jobs()
    {
        peer_managing_thread.join();
    }

    int peer_comm_server::process_custom_messages()
    {
        return self::process_next_message();
    }

    void peer_comm_server::peer_managing_loop()
    {
        util::mask_signal();

        LOG_INFO << "Started peer managing thread.";

        uint16_t peer_managing_counter = 0;
        uint16_t known_connections_counter = 0;
        uint16_t available_capacity_counter = 0;

        while (!is_shutting_down)
        {
            peer_managing_counter++;
            known_connections_counter++;
            available_capacity_counter++;

            if (known_connections_counter % 40 == 0)
            {
                maintain_known_connections();
                known_connections_counter = 0;
            }

            if (available_capacity_counter % 300 == 0)
            {
                status::set_available_mesh_capacity(p2p::calculate_available_capacity());

                // Send available peer capacity if peer max connections is configured.
                if (conf::cfg.mesh.max_connections != 0)
                    p2p::send_available_capacity_announcement(status::get_available_mesh_capacity());
            }

            // Start peer list request loop if dynamic peer discovery is enabled.
            if (conf::cfg.mesh.peer_discovery.enabled)
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
        std::vector<conf::peer_ip_port> known_remotes;

        // Keeps challenge-verified known peers list.
        std::set<conf::peer_ip_port> verified_remotes;

        {
            std::scoped_lock<std::mutex> lock(sessions_mutex);
            for (const p2p::peer_comm_session &session : sessions)
            {
                if (!session.known_ipport)
                    continue;

                if (session.state != comm::SESSION_STATE::CLOSED)
                    known_remotes.push_back(session.known_ipport.value());

                if (session.challenge_status == comm::CHALLENGE_STATUS::CHALLENGE_VERIFIED)
                    verified_remotes.emplace(session.known_ipport.value());
            }
        }

        // Update the central status holder.
        status::set_peers(verified_remotes);

        // Update global known remote count when new connections are made.
        known_remote_count = known_remotes.size();

        // We copy the required known peer list to a local list within a mutex.
        // This avoids the need for a long-lived mutex lock while all connections are attempted.
        std::vector<peer_properties> peer_check_list;
        {
            std::scoped_lock<std::mutex> lock(req_known_remotes_mutex);
            peer_check_list = req_known_remotes;
        }

        bool connections_changed = false;
        std::vector<conf::peer_ip_port> failed_nodes;

        for (const auto &peer : peer_check_list)
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

            if (peer.ip_port.host_address.empty())
            {
                LOG_DEBUG << "Skip connecting to known peer with blank host address " << peer.ip_port.to_string();
                continue;
            }

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
                {
                    LOG_DEBUG << "Outbound connection hpws error:" << error.first << " " << error.second;
                    if (conf::cfg.mesh.peer_discovery.enabled)
                    {
                        failed_nodes.push_back(peer.ip_port);
                        connections_changed = true;
                    }
                }
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
                    p2p::peer_comm_session session(this->violation_tracker, host_address, std::move(client), client.is_ipv4, false, metric_thresholds);

                    // Skip if this peer is banned due to corebill violations.
                    if (violation_tracker.is_banned(host_address))
                    {
                        LOG_DEBUG << "Skipping connecting to banned peer " << host_address;
                        continue;
                    }

                    session.known_ipport.emplace(peer.ip_port);
                    known_remote_count++;

                    std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                    new_sessions.emplace_back(std::move(session));
                    connections_changed = true;
                }
            }
        }
        if (conf::cfg.mesh.peer_discovery.enabled && connections_changed)
        {
            // Copy failed attempt data from failed_nodes to req_known_remotes.
            std::scoped_lock<std::mutex> lock(req_known_remotes_mutex);

            for (auto it = req_known_remotes.begin(); it != req_known_remotes.end();)
            {
                const auto itr = std::find(failed_nodes.begin(), failed_nodes.end(), it->ip_port);
                if (itr != failed_nodes.end())
                {
                    it->failed_attempts++;
                    LOG_DEBUG << "Failed attempts: " << it->failed_attempts << " for peer " << it->ip_port.to_string();
                }
                else if (it->failed_attempts > 0) // Reset failed attempts count if the connection succeeds.
                {
                    it->failed_attempts = 0;
                    LOG_DEBUG << "Failed attempts reset for peer " << it->ip_port.to_string();
                }

                if (it->failed_attempts >= PEER_FAILED_THRESHOLD)
                {
                    LOG_INFO << "Removed " << it->ip_port.to_string() << " from known peer list due to unavailability.";
                    // Add the dead nodes ip data to reject same peer from peer discovery responses.
                    dead_known_peers.emplace(it->ip_port.to_string(), DEAD_PEER_TIMEOUT);
                    it = req_known_remotes.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
    }
    /**
     * Check whether the node is weakly connected or strongly connected.
     */
    void peer_comm_server::detect_if_weakly_connected()
    {
        // If the node is already weakly connected, check every 2 seconds whether we are now strongly connected.
        // Otherwise check every 60 seconds. This makes it harder to become weakly connected and easier to get out of it.
        // This can help with unnessary flooding of forwarded messages across the network.
        bool weakly_connected = status::get_weakly_connected();
        if (connected_status_check_counter == (weakly_connected ? 20 : 600))
        {
            // Get the count of peers which are unl nodes.
            // One is added to peer count only if we are a unl node, to reflect the self connection.
            const int connected_peer_count = std::count_if(sessions.begin(), sessions.end(), [](const p2p::peer_comm_session &session)
                                                           { return session.is_unl; }) +
                                             (conf::cfg.node.is_unl ? 1 : 0);
            const bool current_state = connected_peer_count < (unl::count() * WEAKLY_CONNECTED_THRESHOLD);
            if (weakly_connected != current_state)
            {
                weakly_connected = !weakly_connected;
                send_peer_requirement_announcement(weakly_connected);
                status::set_weakly_connected(weakly_connected);

                if (weakly_connected)
                    LOG_WARNING << "Became weakly connected.";
                else
                    LOG_INFO << "No longer weakly connected.";
            }
            connected_status_check_counter = 0;
        }
        connected_status_check_counter++;
    }
} // namespace p2p