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

bool validate_peer_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp, uint16_t version);

} // namespace p2p

#endif