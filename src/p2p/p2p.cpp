#include <iostream>
#include "../sock/socket_server.hpp"
#include "../sock/socket_client.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"

namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

namespace p2p
{
/**
 * Peer connections exposing to the application
 */
std::unordered_map<std::string, sock::socket_session<peer_outbound_message> *> peer_connections;

/**
 * Peer session handler instance. This instance's methods will be fired for any peer socket activity.
 */
p2p::peer_session_handler global_peer_session_handler;

/**
 * IO context used by the  boost library in creating sockets
 */
net::io_context ioc;

/**
 * SSL context used by the  boost library in providing tls support
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

std::map<std::string, time_t> recent_peer_msghash;

int init()
{
    //Entry point for p2p which will start peer connections to other nodes
    start_peer_connections();

    return 0;
}

void start_peer_connections()
{
    auto address = net::ip::make_address(conf::cfg.listenip);

    //setting up the message max message size. Retrieve it from config
    // At the moment same settings are used to initialize a new server and client
    sess_opts.max_message_size = conf::cfg.peermaxsize;

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

        std::this_thread::sleep_for(std::chrono::milliseconds(conf::cfg.roundtime * 4));
    }
}

/**
 * Validate the incoming p2p message. Check for message version, timestamp and signature.
 * 
 * @param message binary message content.
 * @param signature binary message signature.
 * @param pubkey binary public key of message originating node.
 * @param timestamp message timestamp.
 * @param version message timestamp.
 * @return whether message is validated or not.
 */
bool validate_peer_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp, uint16_t version)
{
    //Validation are prioritzed base on expensiveness of validation.
    //i.e - signature validation is done at the end.

    std::time_t time_now = std::time(nullptr);

    //check protocol version of message whether it is greater than minimum supported protocol version.
    if (version < util::MIN_PEERMSG_VERSION)
    {
        LOG_DBG << "Recieved message is from unsupported version";
        return false;
    }

    // validate if the message is not from a node of current node's unl list.
    if (!conf::cfg.unl.count(pubkey.data()))
    {
        LOG_DBG << "pubkey verification failed";
        return false;
    }

    //check message timestamp.  < timestamp now - 4* round time.
    /*todo:this might change to check only current stage related. (Base on how consensus algorithm implementation take shape)
    check message stage is for valid stage(node's current consensus stage - 1)
    */
    if (timestamp < (time_now - conf::cfg.roundtime * 4))
    {
        LOG_DBG << "Recieved message from peer is old";
        return false;
    }

    //verify message signature.
    //this should be the last validation since this is bit expensive
    auto signature_verified = crypto::verify(message, signature, pubkey);

    if (signature_verified != 0)
    {
        LOG_DBG << "Signature verification failed";
        return false;
    }

    // After signature is verified, get message hash and see wheteher
    // message is already recieved -> abandon if duplicate.
    auto messageHash = crypto::sha_512_hash(message, "PEERMSG", 7);

    if (recent_peer_msghash.count(messageHash) == 0)
    {
        recent_peer_msghash.try_emplace(std::move(messageHash), timestamp);
    }
    else
    {
        LOG_DBG << "Duplicate message";
        return false;
    }

    return true;
}

} // namespace p2p