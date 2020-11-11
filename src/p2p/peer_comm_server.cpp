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
                                       const uint64_t max_msg_size, std::list<conf::peer_properties> &req_known_remotes)
        : comm::comm_server<peer_comm_session>("Peer", port, metric_thresholds, max_msg_size),
          req_known_remotes(req_known_remotes)
    {
    }

    void peer_comm_server::start_custom_jobs()
    {
        // known_peers_thread = std::thread(&peer_comm_server::peer_monitor_loop, this);
        req_peers_thread = std::thread(&peer_comm_server::peer_list_request_loop, this);
    }

    void peer_comm_server::stop_custom_jobs()
    {
        // known_peers_thread.join();
        req_peers_thread.join();
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

    void peer_comm_server::peer_list_request_loop()
    {
        util::mask_signal();

        //LOG_INFO << "Started peer monitor.";

        while (!is_shutting_down)
        {
            // Find already connected known remote parties list.
            std::list<conf::peer_properties> known_remotes;

            {
                std::scoped_lock<std::mutex> lock(sessions_mutex);
                for (const p2p::peer_comm_session &session : sessions)
                {
                    if (session.state != comm::SESSION_STATE::CLOSED && !session.known_ipport.host_address.empty())
                        known_remotes.push_back(session.known_ipport);
                }
            }

            if (known_remotes.size() > 0) {
                p2p::send_peer_list_request();
            }

            if (conf::cfg.peermaxknowncons != 0 && known_remotes.size() >= conf::cfg.peermaxknowncons)
            {
                util::sleep(5000);
            }
            else
            {
                util::sleep(1000);
            }
        }

        //LOG_INFO << "Stopped peer monitor.";
    }

    void peer_comm_server::maintain_known_connections()
    {
        // Find already connected known remote parties list.
        std::list<conf::peer_properties> known_remotes;

        {
            std::scoped_lock<std::mutex> lock(sessions_mutex);
            for (const p2p::peer_comm_session &session : sessions)
            {
                if (session.state != comm::SESSION_STATE::CLOSED && !session.known_ipport.host_address.empty())
                    known_remotes.push_back(session.known_ipport);
            }
        }

        if (conf::cfg.peermaxknowncons == 0 || known_remotes.size() < conf::cfg.peermaxknowncons)
        {
            std::scoped_lock<std::mutex> lock(req_known_remotes_mutex);

            for (const auto &ipport : req_known_remotes)
            {
                if (is_shutting_down)
                    break;

                // Check if we are already connected to this remote party.
                if (std::find_if(known_remotes.begin(), known_remotes.end(), [&](const conf::peer_properties &p) { return p.host_address == ipport.host_address; }) != known_remotes.end())
                    continue;

                std::string_view host = ipport.host_address;
                const uint16_t port = ipport.port;
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
                        session.known_ipport = ipport;

                        std::scoped_lock<std::mutex> lock(new_sessions_mutex);
                        new_sessions.emplace_back(std::move(session));
                    }
                }
            }
        }
    }

} // namespace p2p