#ifndef _HP_P2P_H_
#define _HP_P2P_H_

namespace p2p
{

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

//p2p message handling
void open_listen();
bool validate_peer_message(const std::string *message, size_t message_size, time_t timestamp, uint16_t version);

//void consensus();

} // namespace p2p

#endif