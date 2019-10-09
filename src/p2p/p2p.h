#ifndef _HP_P2P_H_
#define _HP_P2P_H_

#include <string>

#include "message.pb.h"

using namespace std;

namespace p2p
{

/*
Protobuf helpers -------------------------------------------------
Purpose of these helper methods is to wrap up protobuf functionality and provide additional functionality
such as message validation. 
Need to improve and add additional functionality once started to use.  
*/

//set message fields of passed of given message.
void set_message(Message &message, int timestamp, string version, string publicKey, string signature, p2p::Message::Messagetype type, string content);

// Serialize the message and store it in the given string.  All message
// fields must be set. Consensus rounds need all fileds.
bool message_serialize_to_string(Message& message,  string* output);

// Parsing the message from binary message string to given message.
bool message_parse_from_string(Message& message, const string& dataString);

//Set proposal inputs from given string vector.
void set_proposal_inputs(Proposal& proposal, vector<string> inputs);

//Set proposal outputs from given string vector.
void set_proposal_outputs(Proposal& proposal, vector<string> outputs);

//Set proposal connections from given string vector.
void set_proposal_connections(Proposal& proposal, vector<string> connections);

//Set proposal state patches from given map of patches.
void set_state_patch(State& state, map<string, string> patches);

// Serialize the proposal message and store it in the given string.  All propsal message
// fields must be set. Consensus rounds need all fileds.
bool proposal_serialize_to_string(Proposal& proposal, string* output);

// Parsing the proposal message from binary string to given message.
bool proposal_parse_from_string(Proposal& proposal, const string& dataString);

// Serialize the npl message and store it in the given string.  All npl message
// fields must be set.
bool npl_serialize_to_string(NPL& npl, string* output);

// Parsing the npl message from binary string to given message.
bool npl_parse_from_string(NPL& npl, const string& dataString);

}

#endif