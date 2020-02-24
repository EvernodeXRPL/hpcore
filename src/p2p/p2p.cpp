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

/**
 * Initializes the p2p subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
int init()
{
    //Entry point for p2p which will start peer connections to other nodes
    return start_peer_connections();
}

/**
 * Cleanup any running processes.
 */
void deinit()
{
    ctx.listener.stop();
}

int start_peer_connections()
{
    const uint64_t metric_thresholds[] = {conf::cfg.peermaxcpm, conf::cfg.peermaxdupmpm, conf::cfg.peermaxbadsigpm, conf::cfg.peermaxbadmpm};
    if (ctx.listener.start(
        conf::cfg.peerport, ".sock-peer", comm::SESSION_TYPE::PEER, true,
        ctx.peer_connections_mutex, metric_thresholds, conf::cfg.peermaxsize) == -1)
        return -1;

    LOG_INFO << "Started listening for incoming peer connections on " << std::to_string(conf::cfg.peerport);

    // Scan peers and trying to keep up the connections if drop. This action is run on a seperate thread.
    ctx.peer_watchdog_thread = std::thread(&peer_connection_watchdog, std::ref(metric_thresholds));
    return 0;
}

// Scan peer connections continually and attempt to maintain the connection if they drop
void peer_connection_watchdog(const uint64_t (&metric_thresholds)[4])
{
    uint16_t loop_counter = 0;

    while (true)
    {
        // Try to establish new connections every 100 iterations.
        if (loop_counter == 100)
        {
            loop_counter = 0;
            for (const auto &ipport : conf::cfg.peers)
            {
                if (ctx.known_peers.find(ipport) == ctx.known_peers.end())
                {
                    std::string_view host = ipport.first;
                    const uint16_t port = ipport.second;
                    LOG_DBG << "Trying to connect: " << host << ":" << std::to_string(port);

                    comm::comm_client client;
                    if (client.start(host, port, metric_thresholds, conf::cfg.peermaxsize) == -1)
                    {
                        LOG_ERR << "Peer connection attempt failed";
                    }
                    else
                    {
                        const bool is_self = (host == conf::SELF_HOST);
                        comm::comm_session session(host, client.read_fd, client.write_fd, comm::SESSION_TYPE::PEER, true, is_self, false, metric_thresholds);
                        session.on_connect();

                        // If the session is still active (because corebill might close the connection immeditately)
                        // We add to the client list as well.
                        if (session.state == comm::SESSION_STATE::ACTIVE)
                        {
                            session.known_ipport = ipport;
                            ctx.peer_clients.try_emplace(ipport, client);
                            ctx.known_peers.emplace(ipport);
                        }
                    }
                }
            }
        }
        loop_counter++;

        std::unordered_set<std::string> clients_to_disconnect;

        for (auto &[uniqueid, session] : ctx.peer_connections)
        {
            bool should_disonnect;
            session.attempt_read(should_disonnect, conf::cfg.peermaxsize);

            if (should_disonnect)
                clients_to_disconnect.emplace(uniqueid);
        }

        {
            //std::lock_guard lock(ctx.peer_connections_mutex);

            for (auto &uniqueid : clients_to_disconnect)
            {
                const auto itr = ctx.peer_connections.find(uniqueid);
                comm::comm_session &session = itr->second;
                session.close();
            }
        }
        util::sleep(10);
    }
}

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
    //std::lock_guard<std::mutex> lock(ctx.peer_connections_mutex);

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
    //std::lock_guard<std::mutex> lock(p2p::ctx.peer_connections_mutex);

    // Find the peer session connected to self.
    const auto peer_itr = ctx.peer_connections.find(conf::cfg.self_peerid);
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
    //std::lock_guard<std::mutex> lock(p2p::ctx.peer_connections_mutex);

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