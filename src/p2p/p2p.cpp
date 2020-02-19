#include "../pchheader.hpp"
#include "../comm/comm_server.hpp"
#include "../comm/comm_client.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"

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
    const uint64_t metric_thresholds[] = {conf::cfg.peermaxcpm, conf::cfg.peermaxdupmpm, conf::cfg.peermaxbadsigpm, conf::cfg.pubmaxbadmpm};
    listener_ctx.server.start(
        conf::cfg.peerport, ".sock-peer", comm::SESSION_TYPE::PEER, true,
        ctx.peer_connections_mutex, metric_thresholds, conf::cfg.peermaxsize);

    LOG_INFO << "Started listening for incoming peer connections on " << std::to_string(conf::cfg.peerport);

    // Scan peers and trying to keep up the connections if drop. This action is run on a seperate thread.
    //ctx.peer_watchdog_thread = std::thread(&peer_connection_watchdog });
}

// // Scan peer connections continually and attempt to maintain the connection if they drop
// void peer_connection_watchdog()
// {
//     while (true)
//     {
//         for (const auto &[peerid, ipport] : conf::cfg.peers)
//         {
//             if (ctx.peer_connections.find(peerid) == ctx.peer_connections.end())
//             {
//                 LOG_DBG << "Trying to connect : " << peerid;
//                 std::make_shared<sock::socket_client<peer_outbound_message>>(listener_ctx.ioc, listener_ctx.ssl_ctx, listener_ctx.global_peer_session_handler, listener_ctx.default_sess_opts)
//                     ->run(ipport.first, ipport.second);
//             }
//         }

//         util::sleep(conf::cfg.roundtime * 4);
//     }
// }

/**
 * Broadcasts the given message to all currently connected outbound peers.
 * @param msg Peer outbound message to be broadcasted.
 * @param send_to_self Whether to also send the message to self (this node).
 */
void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self)
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
        if (!send_to_self && session.is_self)
            continue;

        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
        session.send(msg);
    }
}

/**
 * Sends the given message to self (this node).
 * @param msg Peer outbound message to be sent to self.
 */
void send_message_to_self(const flatbuffers::FlatBufferBuilder &fbuf)
{
    //Send while locking the peer_connections.
    std::lock_guard<std::mutex> lock(p2p::ctx.peer_connections_mutex);

    // Find the peer session connected to self.
    const auto peer_itr = ctx.peer_connections.find(conf::cfg.self_peer_id);
    if (peer_itr != ctx.peer_connections.end())
    {
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

        const comm::comm_session &session = peer_itr->second;
        session.send(msg);
    }
}

/**
 * Sends the given message to a random peer (except self).
 * @param msg Peer outbound message to be sent to peer.
 */
void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf)
{
    //Send while locking the peer_connections.
    std::lock_guard<std::mutex> lock(p2p::ctx.peer_connections_mutex);

    const size_t connected_peers = ctx.peer_connections.size();
    if (connected_peers == 0)
    {
        LOG_DBG << "No peers to send (not even self).";
        return;
    }
    else if (connected_peers == 1 && ctx.peer_connections.begin()->second.is_self)
    {
        LOG_DBG << "Only self is connected.";
        return;
    }

    while (true)
    {
        // Initialize random number generator with current timestamp.
        const int random_peer_index = (rand() % connected_peers); // select a random peer index.
        auto it = ctx.peer_connections.begin();
        std::advance(it, random_peer_index); //move iterator to point to random selected peer.

        //send message to selected peer.
        const comm::comm_session &session = it->second;
        if (!session.is_self) // Exclude self peer.
        {
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            session.send(msg);
            break;
        }
    }
}

} // namespace p2p