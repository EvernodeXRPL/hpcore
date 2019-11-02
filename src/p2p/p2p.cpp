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

// The set of recent peer message hashes used for duplicate detection.
std::unordered_set<std::string> recent_peermsg_hashes;

// The supporting list of recent peer message hashes used for adding and removing hashes from
// the 'recent_peermsg_hashes' in a first-in-first-out manner.
std::list<const std::string *> recent_peermsg_hashes_list;

// Maximum number of recent message hashes to remember.
static const int16_t MAX_RECENT_MSG_HASHES = 200;

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

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

bool is_message_duplicate(std::string_view message)
{
    // Get message hash and see whether message is already recieved -> abandon if duplicate.
    std::string hash = crypto::get_hash(message);

    auto itr = recent_peermsg_hashes.find(hash);
    if (itr == recent_peermsg_hashes.end()) // Not found
    {
        // Add the new message hash to the list.
        auto [newitr, success] = recent_peermsg_hashes.emplace(hash);

        // Insert a pointer to the stored hash value into the ordered list of hashes.
        recent_peermsg_hashes_list.push_back(&(*newitr));

        // Remove old hashes if exceeding max hash count.
        if (recent_peermsg_hashes_list.size() > MAX_RECENT_MSG_HASHES)
        {
            const std::string &oldesthash = *recent_peermsg_hashes_list.front();
            recent_peermsg_hashes.erase(oldesthash);

            recent_peermsg_hashes_list.pop_front();
        }

        return false;
    }

    LOG_DBG << "Duplicate peer message.";
    return true;
}

} // namespace p2p