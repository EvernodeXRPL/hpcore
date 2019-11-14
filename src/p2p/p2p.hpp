#ifndef _HP_P2P_
#define _HP_P2P_

#include "../pchheader.hpp"
#include "../sock/socket_session.hpp"
#include "../usr/user_input.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    
struct proposal
{
    std::string pubkey;
    uint64_t timestamp;
    uint64_t time;
    uint8_t stage;
    std::string lcl;
    std::set<std::string> users;
    std::set<std::string> hash_inputs;
    std::set<std::string> hash_outputs;
};

struct nonunl_proposal
{
    std::unordered_map<std::string, const std::list<usr::user_submitted_message>> user_messages;
};

struct npl_message
{
    std::string data;
};

struct message_collection
{
    std::list<proposal> proposals;
    std::mutex proposals_mutex;                    // Mutex for proposals access race conditions.
    
    std::list<nonunl_proposal> nonunl_proposals;
    std::mutex nonunl_proposals_mutex;            // Mutex for non-unl proposals access race conditions.

    // NPL messages are stored as string list because we are feeding the npl messages as it is (byte array) to the contract.
    std::list<std::string> npl_messages;          
    std::mutex npl_messages_mutex;                 // Mutex for npl_messages access race conditions.
};

struct connected_context
{
    // Holds all the messages until they are processed by consensus.
    message_collection collected_msgs;

    // Set of currently connected outbound peer connections mapped by the uniqueid of socket session.
    std::unordered_map<std::string, sock::socket_session<peer_outbound_message> *> peer_connections;
    std::mutex peer_connections_mutex; // Mutex for peer connections access race conditions.

    // Peer connection watchdog runs on this thread.
    std::thread peer_watchdog_thread;
};
extern connected_context ctx;

struct listener_context
{
    // Peer session handler instance. This instance's methods will be fired for any peer socket activity.
    p2p::peer_session_handler global_peer_session_handler;

    // IO context used by the  boost library in creating sockets
    net::io_context ioc;

    // SSL context used by the boost library in providing tls support
    ssl::context ssl_ctx{ssl::context::tlsv13};

    // The thread the peer listener is running on.
    std::thread listener_thread;

    // Used to pass down the default settings to the socket session
    sock::session_options default_sess_opts;
};

int init();

//p2p message handling
void start_peer_connections();

void peer_connection_watchdog();

void broadcast_message(const peer_outbound_message msg, bool self_recieve);

} // namespace p2p

#endif