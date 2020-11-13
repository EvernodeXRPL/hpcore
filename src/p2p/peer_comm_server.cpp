#include "../comm/comm_server.hpp"
#include "../util.hpp"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../ledger.hpp"
#include "peer_comm_server.hpp"
#include "peer_comm_session.hpp"
#include "self_node.hpp"

namespace p2p
{
    peer_comm_server::peer_comm_server(const uint16_t port, const uint64_t (&metric_thresholds)[4],
                                       const uint64_t max_msg_size, std::vector<conf::peer_properties> &req_known_remotes)
        : comm::comm_server<peer_comm_session>("Peer", port, metric_thresholds, max_msg_size),
          req_known_remotes(req_known_remotes)
    {
    }

    void peer_comm_server::start_custom_jobs()
    {
        // known_peers_thread = std::thread(&peer_comm_server::peer_monitor_loop, this);
        if (conf::cfg.dynamicpeerdiscovery)
        {
            peer_list_request_thread = std::thread(&peer_comm_server::peer_list_request_loop, this);
        }
        if (conf::cfg.peermaxcons != 0)
        {
            available_capacity_announcement_thread = std::thread(&peer_comm_server::available_capacity_announcement_loop, this);
        }
    }

    void peer_comm_server::stop_custom_jobs()
    {
        // known_peers_thread.join();
        // Start peer list request loop is dynamic peer discovery is enabled.
        if (conf::cfg.dynamicpeerdiscovery)
        {
            peer_list_request_thread.join();
        }
        // Start sending available capacity updates if peermaxcons cap is not 0(unlimited).
        if (conf::cfg.peermaxcons != 0)
        {
            available_capacity_announcement_thread.join();
        }
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

    void peer_comm_server::available_capacity_announcement_loop()
    {
        util::mask_signal();

        LOG_DEBUG << "Started available capacity announcement loop.";

        while (!is_shutting_down)
        {
            // If peermaxknowncons is 0(unlimited) available capacity is max connections - total active sessions.
            // Otherwise max connections - max known connections - active unknown connections.
            if (conf::cfg.peermaxknowncons == 0)
            {
                available_capacity = conf::cfg.peermaxcons - sessions.size();
            }
            else
            {
                available_capacity = conf::cfg.peermaxcons - conf::cfg.peermaxknowncons - (sessions.size() - known_remote_count);
            }

            p2p::send_available_capacity_announcement(available_capacity);

            util::sleep(1000);
        }

        LOG_DEBUG << "Stopped available capacity announcement loop.";
    }

    void peer_comm_server::peer_list_request_loop()
    {
        util::mask_signal();

        LOG_INFO << "Started peer list request loop.";

        while (!is_shutting_down)
        {
            if (known_remote_count > 0)
            {
                p2p::send_peer_list_request();
            }

            // If max known peer connection cap is reached then periodically request peer list from random known peer.
            // Otherwise frequently request peer list from a random known peer.
            // Peer discovery time interval can be configured in the config.
            if (conf::cfg.peermaxknowncons != 0 && known_remote_count >= conf::cfg.peermaxknowncons)
            {
                util::sleep(conf::cfg.peerdiscoverytime * 5);
            }
            else
            {
                util::sleep(conf::cfg.peerdiscoverytime);
            }
        }

        LOG_INFO << "Stopped peer list request loop.";
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

        std::scoped_lock<std::mutex> lock(req_known_remotes_mutex);

        for (const auto &peer : req_known_remotes)
        {
            if (is_shutting_down)
                break;

            // Break if known peer cap is reached.
            if (conf::cfg.peermaxknowncons != 0 && known_remotes.size() == conf::cfg.peermaxknowncons)
                break;

            // Break if mac peer connection cap is reached.
            if (conf::cfg.peermaxcons != 0 && (sessions.size() + new_sessions.size()) >= conf::cfg.peermaxcons)
                break;

            // Break if the peer has no free slots.
            if (peer.available_capacity == 0)
                break;

            // Check if we are already connected to this remote party.
            if (std::find_if(known_remotes.begin(), known_remotes.end(),
                             [&](const conf::ip_port_prop &p) { return p.host_address == peer.ip_port.host_address && p.port == peer.ip_port.port; }) != known_remotes.end())
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
                    session.known_ipport.emplace(peer.ip_port);
                    known_remotes.push_back(peer.ip_port);

                    std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                    new_sessions.emplace_back(std::move(session));
                }
            }
        }

        // Update global known remote count when new connections are made.
        known_remote_count = known_remotes.size();
    }

} // namespace p2p