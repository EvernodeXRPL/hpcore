#ifndef _HP_P2P_H_
#define _HP_P2P_H_

namespace p2p
{


struct peer_context
{
    std::map<std::string, time_t> recent_peer_msghash; // hash of recent peer messages.
    //std::vector<NPL> npl_messages; //npl messages recieved
    std::map<std::string, std::vector<std::string>> local_pending_inputs;  //inputs from users: IP:PORT;pubkeyhex -> [ ordered list of input packets ]
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
/*
Protobuf helpers -------------------------------------------------
Purpose of these helper methods is to wrap up protobuf functionality and provide additional functionality
such as message validation. 
Need to improve and add additional functionality once started to use.  
*/

// void set_message(Message &message, const int timestamp, const std::string &version, const std::string &publicKey, const std::string &signature, p2p::Message::Messagetype type, const std::string &content);
// bool message_serialize_to_string(Message &message, std::string &output);
// bool message_parse_from_string(Message &message, const std::string &dataString);
// void set_proposal_inputs(Proposal &proposal, const std::vector<std::string> &inputs);
// void set_proposal_outputs(Proposal &proposal, const std::vector<std::string> &outputs);
// void set_proposal_connections(Proposal &proposal, const std::vector<std::string> &connections);
// void set_state_patch(State &state, const std::map<std::string, std::string> &patches);
// bool proposal_serialize_to_string(Proposal &proposal, std::string &output);
// bool proposal_parse_from_string(Proposal &proposal, const std::string &dataString);
// bool npl_serialize_to_string(NPL &npl, std::string &output);
// bool npl_parse_from_string(NPL &npl, const std::string &dataString);


//p2p message handling
void open_listen();
//bool validate_peer_message(const p2p::Message &peer_message, const std::string &message);

//void consensus();

} // namespace p2p

#endif