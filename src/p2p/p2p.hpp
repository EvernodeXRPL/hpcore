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

struct peer_context
{
    std::map<std::string, time_t> recent_peer_msghash; // hash of recent peer messages.
    //std::vector<NPL> npl_messages; //npl messages recieved
    std::map<std::string, std::vector<std::string>> local_pending_inputs; //inputs from users: IP:PORT;pubkeyhex -> [ ordered list of input packets ]
};

struct consensus_context
{
    // std::map<std::string, Proposal> proposals; //msg.pubkey + '-' + msg.stage => proposal message
    // int stage;
    // std::time_t novel_proposal_time;
    // std::string lcl;
};

//global peer context
extern peer_context peer_ctx;

//global consenus context
extern consensus_context consensus_ctx;

int init();

//p2p message handling
void start_peer_connections();

void peer_connection_watchdog();

bool validate_peer_message(const std::string_view message, const std::string_view signature, time_t timestamp, uint16_t version, const std::string_view pubkey);

//void consensus();

} // namespace p2p

#endif