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

struct history_request
{
    std::string lcl;
};

struct history_ledger
{
    std::string lcl;
    std::vector<uint8_t> raw_ledger;
};

struct history_response
{
    std::map<uint64_t,const history_ledger> hist_ledgers;
};

struct message_collection
{
    std::list<proposal> proposals;
    std::mutex proposals_mutex; // Mutex for proposals access race conditions.

    std::list<nonunl_proposal> nonunl_proposals;
    std::mutex nonunl_proposals_mutex; // Mutex for non-unl proposals access race conditions.
};

/**
 * Holds all the messages until they are processed by consensus.
 */
extern message_collection collected_msgs;

/**
 * This is used to store active peer connections mapped by the unique key of socket session
 */
extern std::unordered_map<std::string, sock::socket_session<peer_outbound_message> *> peer_connections;
extern std::mutex peer_connections_mutex; // Mutex for peer connections access race conditions.

int init();

//p2p message handling
void start_peer_connections();

void peer_connection_watchdog();

void broadcast_message(const peer_outbound_message msg);

void send_message_to_random_peer(peer_outbound_message msg);

void send_message_to_peer(std::string peer_session_id, peer_outbound_message msg);

} // namespace p2p

#endif