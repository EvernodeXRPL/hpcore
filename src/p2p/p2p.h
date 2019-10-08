#ifndef _HP_P2P_H_
#define _HP_P2P_H_

#include <string>

#include "message.pb.h"

using namespace std;

namespace p2p
{

void set_message(Message &message, int timestamp, string version, string publicKey, string signature, p2p::Message::Messagetype type, string content);

bool message_serialize_to_string(Message& message,  string* output);

bool message_parse_from_string(Message& message, const string& dataString);

void set_proposal_inputs(Proposal& proposal, vector<string> inputs);

void set_proposal_outputs(Proposal& proposal, vector<string> outputs);

void set_proposal_connections(Proposal& proposal, vector<string> connections);

void set_state_patch(State& state, map<string, string> patches);

bool proposal_serialize_to_string(Proposal& proposal, string* output);

bool proposal_parse_from_string(Proposal& proposal, const string& dataString);

bool npl_serialize_to_string(NPL& npl, string* output);

bool npl_parse_from_string(NPL& npl, const string& dataString);

}

#endif