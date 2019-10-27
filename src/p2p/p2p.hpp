#ifndef _HP_P2P_H_
#define _HP_P2P_H_

#include <unordered_set>
#include <unordered_map>
#include <list>
#include <mutex>
#include "../sock/socket_session.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    
struct proposal
{
    std::string pubkey;
    int64_t timestamp;
    int64_t time;
    int8_t stage;
    std::string lcl;
    std::unordered_set<std::string> users;
    std::unordered_map<std::string, const std::vector<util::hash_buffer>> raw_inputs;
    std::unordered_set<std::string> hash_inputs;
    std::unordered_map<std::string, util::hash_buffer> raw_outputs;
    std::unordered_set<std::string> hash_outputs;
};

struct message_collection
{
    std::list<proposal> proposals;
    std::mutex proposals_mutex;     // Mutex for proposals access race conditions.
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

/**
 * This is used to store hash of recent peer messages: messagehash -> timestamp of message
 */
extern std::map<std::string, int64_t> recent_peer_msghash;

int init();

//p2p message handling
void start_peer_connections();

void peer_connection_watchdog();

} // namespace p2p

#endif