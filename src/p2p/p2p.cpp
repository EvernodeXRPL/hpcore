#include "../pchheader.hpp"
#include "../sock/socket_server.hpp"
#include "../sock/socket_client.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"

namespace ssl = boost::asio::ssl;

namespace p2p
{

// Holds global connected-peers and related objects.
connected_context ctx;

// Holds objects used by socket listener.
listener_context listener_ctx;

int init()
{
    //Entry point for p2p which will start peer connections to other nodes
    start_peer_connections();

    return 0;
}

void start_peer_connections()
{
    boost::asio::ip::address address = net::ip::make_address(conf::cfg.listenip);

    // Setting up the message max size. Retrieve it from config
    listener_ctx.default_sess_opts.max_socket_read_len = conf::cfg.peermaxsize;
    listener_ctx.default_sess_opts.max_rawbytes_per_minute = conf::cfg.peermaxcpm;
    listener_ctx.default_sess_opts.max_dupmsgs_per_minute = conf::cfg.peermaxdupmpm;
    listener_ctx.default_sess_opts.max_badmsgs_per_minute = conf::cfg.peermaxbadmpm;
    listener_ctx.default_sess_opts.max_badsigmsgs_per_minute = conf::cfg.peermaxbadsigpm;

    // Start listening to peers
    std::make_shared<sock::socket_server<peer_outbound_message>>(
        listener_ctx.ioc,
        listener_ctx.ssl_ctx,
        tcp::endpoint{address, conf::cfg.peerport},
        listener_ctx.global_peer_session_handler,
        listener_ctx.default_sess_opts)
        ->run();

    LOG_INFO << "Started listening for incoming peer connections on " << conf::cfg.listenip << ":" << conf::cfg.peerport;

    // Scan peers and trying to keep up the connections if drop. This action is run on a seperate thread.
    ctx.peer_watchdog_thread = std::thread([&] { peer_connection_watchdog(); });

    // Peer listener thread.
    listener_ctx.listener_thread = std::thread([&] { listener_ctx.ioc.run(); });
}

// Scan peer connections continually and attempt to maintain the connection if they drop
void peer_connection_watchdog()
{
    while (true)
    {
        for (const auto &[peerid, ipport] : conf::cfg.peers)
        {
            if (ctx.peer_connections.find(peerid) == ctx.peer_connections.end())
            {
                LOG_DBG << "Trying to connect : " << peerid;
                std::make_shared<sock::socket_client<peer_outbound_message>>(listener_ctx.ioc, listener_ctx.ssl_ctx, listener_ctx.global_peer_session_handler, listener_ctx.default_sess_opts)
                    ->run(ipport.first, ipport.second);
            }
        }

        util::sleep(conf::cfg.roundtime * 4);
    }
}

/**
 * Broadcasts the given message to all currently connected outbound peers.
 */
void broadcast_message(const peer_outbound_message msg, bool self_recieve)
{
    if (ctx.peer_connections.size() == 0)
    {
        LOG_DBG << "No peers to broadcast (not even self). Waiting until at least one peer connects.";
        while (ctx.peer_connections.size() == 0)
            util::sleep(100);
    }

    //Broadcast while locking the peer_connections.
    std::lock_guard<std::mutex> lock(ctx.peer_connections_mutex);
    for (const auto &[k, session] : ctx.peer_connections)
    {
        if (!self_recieve && session->address == "0.0.0.0")
            continue;
        std::cout << "Sending to peer :" << session->uniqueid << std::endl;
        session->send(msg);
    }
}

} // namespace p2p