#ifndef _HP_P2P_
#define _HP_P2P_

#include "../pchheader.hpp"
#include "../sock/socket_session.hpp"
#include "../usr/user_input.hpp"
#include "peer_session_handler.hpp"
#include "../statefs/hasher.hpp"

namespace p2p
{

struct proposal
{
    std::string pubkey;
    uint64_t timestamp;
    uint64_t time;
    uint8_t stage;
    std::string lcl;
    std::string curr_hash_state;
    std::set<std::string> users;
    std::set<std::string> hash_inputs;
    std::set<std::string> hash_outputs;
};

struct nonunl_proposal
{
    std::unordered_map<std::string, const std::list<usr::user_submitted_message>> user_messages;
};

struct history_request
{
    std::string minimum_lcl;
    std::string required_lcl;
};

struct history_ledger
{
    std::string state;
    std::string lcl;
    std::vector<uint8_t> raw_ledger;
};

enum LEDGER_RESPONSE_ERROR
{
    NONE = 0,
    INVALID_MIN_LEDGER = 1,
    REQ_LEDGER_NOT_FOUND = 2
};

struct history_response
{
    std::map<uint64_t, const history_ledger> hist_ledgers;
    LEDGER_RESPONSE_ERROR error;
};

struct npl_message
{
    std::string data;
};

struct state_request
{
    std::string parent_path;
    bool is_file;
    int32_t block_id;
};

struct state_response
{
    std::string full_path;
    bool is_file;
};

struct state_fs_hash_entry
{
    bool is_file;
    hasher::B2H hash;
};

struct block_response
{
    std::string path;
    uint32_t block_id;
    std::vector<uint8_t> data;
};

struct message_collection
{
    std::list<proposal> proposals;
    std::mutex proposals_mutex; // Mutex for proposals access race conditions.

    std::list<nonunl_proposal> nonunl_proposals;
    std::mutex nonunl_proposals_mutex; // Mutex for non-unl proposals access race conditions.

    // NPL messages are stored as string list because we are feeding the npl messages as it is (byte array) to the contract.
    std::list<std::string> npl_messages;
    std::mutex npl_messages_mutex; // Mutex for npl_messages access race conditions.

    std::list<std::string> state_response;
    std::mutex state_response_mutex; // Mutex for state response access race conditions.
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

void broadcast_message(const peer_outbound_message msg, bool send_to_self);

void send_message_to_random_peer(peer_outbound_message msg);

void send_message_to_peer(std::string peer_session_id, peer_outbound_message msg);

} // namespace p2p

#endif