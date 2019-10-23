#ifndef _HP_P2P_H_
#define _HP_P2P_H_

#include <unordered_map>
#include "../sock/socket_session.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    
struct proposal
{
    std::string pubkey;
    uint64_t timestamp;
    int8_t stage;
    uint64_t time;
    std::string lcl;
    std::vector<std::string> users;
    std::unordered_map<std::string, std::string> raw_inputs;
    std::vector<std::string> hash_inputs;
    std::unordered_map<std::string, std::string> raw_outputs;
    std::vector<std::string> hash_outputs;
};

struct message_collection
{
    std::vector<proposal> proposals;
};

/**
 * Holds all the messages until they are processed by consensus.
 */
extern message_collection collected_msgs;

/**
 * This is used to store active peer connections mapped by the unique key of socket session
 */
extern std::unordered_map<std::string, sock::socket_session<peer_outbound_message> *> peer_connections;

/**
 * This is used to store hash of recent peer messages: messagehash -> timestamp of message
 */
extern std::map<std::string, time_t> recent_peer_msghash;

int init();

//p2p message handling
void start_peer_connections();

void peer_connection_watchdog();

} // namespace p2p

#endif