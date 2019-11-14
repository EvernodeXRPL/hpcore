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
sock::session_options default_sess_opts;

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
    default_sess_opts.max_socket_read_len = conf::cfg.peermaxsize;
    default_sess_opts.max_rawbytes_per_minute = conf::cfg.peermaxcpm;
    default_sess_opts.max_dupmsgs_per_minute = conf::cfg.peermaxdupmpm;
    default_sess_opts.max_badmsgs_per_minute = conf::cfg.peermaxbadmpm;
    default_sess_opts.max_badsigmsgs_per_minute = conf::cfg.peermaxbadsigpm;

    // Start listening to peers
    std::make_shared<sock::socket_server<peer_outbound_message>>(
        ioc,
        ctx,
        tcp::endpoint{address, conf::cfg.peerport},
        global_peer_session_handler,
        default_sess_opts)
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
        for (const auto &[peerid, ipport] : conf::cfg.peers)
        {
            if (peer_connections.find(peerid) == peer_connections.end())
            {
                LOG_DBG << "Trying to connect : " << peerid;
                std::make_shared<sock::socket_client<peer_outbound_message>>(ioc, ctx, global_peer_session_handler, default_sess_opts)
                    ->run(ipport.first, ipport.second);
            }
        }

        util::sleep(200);
    }
}

/**
 * Broadcasts the given message to all currently connected outbound peers.
 */
void broadcast_message(const peer_outbound_message msg)
{
    if (p2p::peer_connections.size() == 0)
    {
        LOG_DBG << "No peers to broadcast (not even self). Waiting until at least one peer connects.";
        while (p2p::peer_connections.size() == 0)
            util::sleep(100);
    }

    //Broadcast while locking the peer_connections.
    std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
    for (const auto &[k, session] : p2p::peer_connections)
        session->send(msg);
}

/**
 * Send the given message to a random peer from currently connected outbound peers.
 */
void send_message_to_random_peer(peer_outbound_message msg)
{
    size_t connected_peers = p2p::peer_connections.size();
    if (connected_peers == 0)
    {
        LOG_DBG << "No peers to send (not even self).";
        return;
    }
    else if (connected_peers == 1)
    {
        LOG_DBG << "Only self is connected."; //todo:check self connection.
        return;
    }

    //Send while locking the peer_connections.
    std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);

    srand(time(0));                                     // Initialize random number generator with current timestamp.
    int random_peer_index = (rand() % connected_peers); // select a random peer index.
    auto it = p2p::peer_connections.begin();
    std::advance(it, random_peer_index); //move iterator to point to random selected peer.

    //send message to selecte peer.
    auto session = it->second;
    if (session->address != "0.0.0.0")
    {
        session->send(msg);
    }
}

} // namespace p2p