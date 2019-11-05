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

/**
 * Holds all the messages until they are processed by consensus.
 */
message_collection collected_msgs;

/**
 * Peer connections exposing to the application
 */
std::unordered_map<std::string, sock::socket_session<peer_outbound_message> *> peer_connections;
std::mutex peer_connections_mutex; // Mutex for peer connections access race conditions.

/**
 * Peer session handler instance. This instance's methods will be fired for any peer socket activity.
 */
p2p::peer_session_handler global_peer_session_handler;

/**
 * IO context used by the  boost library in creating sockets
 */
net::io_context ioc;

/**
 * SSL context used by the boost library in providing tls support
 */
ssl::context ctx{ssl::context::tlsv13};

/**
 * The thread the peer server and client is running on. (not exposed out of this namespace)
 * Peer connection watchdog runs on this thread.
 */
std::thread peer_watchdog_thread;

/**
 * The thread the peer listener is running on. (not exposed out of this namespace)
 */
std::thread peer_thread;

/**
 * Used to pass down the default settings to the socket session
 */
sock::session_options sess_opts;

int init()
{
    //Entry point for p2p which will start peer connections to other nodes
    start_peer_connections();

    return 0;
}

void start_peer_connections()
{
    auto address = net::ip::make_address(conf::cfg.listenip);

    //setting up the message max size. Retrieve it from config
    // At the moment same settings are used to initialize a new server and client
    sess_opts.max_message_size = conf::cfg.peermaxsize;
    sess_opts.max_bytes_per_minute = conf::cfg.peermaxcpm;

    // Start listening to peers
    std::make_shared<sock::socket_server<peer_outbound_message>>(
        ioc,
        ctx,
        tcp::endpoint{address, conf::cfg.peerport},
        global_peer_session_handler,
        sess_opts)
        ->run();

    LOG_INFO << "Started listening for incoming peer connections on " << conf::cfg.listenip << ":" << conf::cfg.peerport;

    // Scan peers and trying to keep up the connections if drop. This action is run on a seperate thread.
    peer_watchdog_thread = std::thread([&] { peer_connection_watchdog(); });

    // Peer listener thread.
    peer_thread = std::thread([&] { ioc.run(); });
}

// Scan peer connections continually and attempt to maintain the connection if they drop
void peer_connection_watchdog()
{
    //todo: implement exit gracefully.
    while (true)
    {
        for (auto &v : conf::cfg.peers)
        {
            if (peer_connections.find(v.first) == peer_connections.end())
            {
                LOG_DBG << "Trying to connect :" << v.second.first << ":" << v.second.second;
                std::make_shared<sock::socket_client<peer_outbound_message>>(ioc, ctx, global_peer_session_handler, sess_opts)
                    ->run(v.second.first, v.second.second);
            }
        }

        util::sleep(200);
    }
}

/**
 * Broadcasts the given message to all currently connected outbound peers.
 */
void broadcast_message(peer_outbound_message msg)
{
    if (p2p::peer_connections.size() == 0)
    {
        LOG_DBG << "No peers to broadcast (not even self). Waiting until at least one peer connects.";
        while (p2p::peer_connections.size() == 0)
            util::sleep(100);
    }

    //Broadcast while locking the peer_connections.
    std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
    for (auto &[k, session] : p2p::peer_connections)
        session->send(msg);
}

} // namespace p2p