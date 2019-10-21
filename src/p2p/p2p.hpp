#ifndef _HP_P2P_H_
#define _HP_P2P_H_

#include <unordered_map>
#include "../sock/socket_session.hpp"

namespace p2p
{
/**
 * This is used to store active peer connections mapped by the unique key of socket session
 */
extern std::unordered_map<std::string, sock::socket_session *> peer_connections;

/**
 * This is used to store hash of recent peer messages: messagehash -> timestamp of message
 */
extern std::map<std::string, time_t> recent_peer_msghash;

//todo:move to consensus namespace
struct consensus_context
{
    // std::map<std::string, Proposal> proposals; //msg.pubkey + '-' + msg.stage => proposal message
    // int stage;
    // std::time_t novel_proposal_time;
    // std::string lcl;
};

//global consenus context
extern consensus_context consensus_ctx;

int init();

//p2p message handling
void start_peer_connections();

void peer_connection_watchdog();

bool validate_peer_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp, uint16_t version);

//void consensus();

} // namespace p2p

#endif