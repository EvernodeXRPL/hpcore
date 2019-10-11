#ifndef _HP_P2P_H_
#define _HP_P2P_H_

#include <string>
#include "message.pb.h"

using namespace std;

namespace p2p
{

struct peer_context
{
    map<string, string> recent_peer_msghash; // hash of recent peer messages.
};

//global peer context
extern peer_context peer_ctx;

/*
Protobuf helpers -------------------------------------------------
Purpose of these helper methods is to wrap up protobuf functionality and provide additional functionality
such as message validation. 
Need to improve and add additional functionality once started to use.  
*/

void set_message(Message &message, const int timestamp, const string &version, const string &publicKey, const string &signature, p2p::Message::Messagetype type, const string &content);

bool message_serialize_to_string(Message &message, string &output);

bool message_parse_from_string(Message &message, const string &dataString);

void set_proposal_inputs(Proposal &proposal, const vector<string>& inputs);

void set_proposal_outputs(Proposal &proposal, const vector<string>& outputs);

void set_proposal_connections(Proposal &proposal, const vector<string>& connections);

void set_state_patch(State &state, const map<string, string>& patches);

bool proposal_serialize_to_string(Proposal &proposal, string &output);

bool proposal_parse_from_string(Proposal &proposal, const string &dataString);

bool npl_serialize_to_string(NPL &npl, string &output);

bool npl_parse_from_string(NPL &npl, const string &dataString);

} // namespace p2p

#endif