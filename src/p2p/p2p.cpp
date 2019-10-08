#include <string>
#include "message.pb.h"
#include "p2p.h"

using namespace std;

namespace p2p {

void set_message(Message &message, int timestamp, string version, string publicKey, string signature, p2p::Message::Messagetype type, string content)
{
    message.set_version(version);
    message.set_timestamp(timestamp);
    message.set_publickey(publicKey);
    message.set_signature(signature);
    message.set_type(type);
    message.set_content(content);
}  


bool message_serialize_to_string(Message& message,  string* output)
{
    if(message.has_publickey() 
        && message.has_signature() 
        && message.has_timestamp() 
        && message.has_type()
        && message.has_version()
        && message.has_content())

    return message.SerializeToString(output);

    else
    return false;
}

bool message_parse_from_string(Message& message, const string& dataString)
{
    return message.ParseFromString(dataString);
}

void set_proposal_inputs(Proposal& proposal, vector<string> inputs)
{
     proposal.mutable_inputs() -> Reserve(inputs.size()); 
    *proposal.mutable_inputs() = {inputs.begin(), inputs.end()};
} 

void set_proposal_outputs(Proposal& proposal, vector<string> outputs)
{
     proposal.mutable_inputs() -> Reserve(outputs.size()); 
    *proposal.mutable_inputs() = {outputs.begin(), outputs.end()};
} 

void set_proposal_connections(Proposal& proposal, vector<string> connections)
{
     proposal.mutable_inputs() -> Reserve(connections.size()); 
    *proposal.mutable_inputs() = {connections.begin(), connections.end()};
}

void set_state_patch(State& state, map<string, string> patches)
{
    //state.mutable_patch().Reserve(patches.size()); 
    *state.mutable_patch() = {patches.begin(), patches.end()};
}

bool proposal_serialize_to_string(Proposal& proposal, string* output)
{
    if(proposal.has_stage() 
        && proposal.has_lcl()
        && proposal.has_state()
        && proposal.has_time()
        && (proposal.inputs_size() == 0)
        && (proposal.outputs_size() == 0))
    return proposal.SerializeToString(output);

    else 
        return false;
}

bool proposal_parse_from_string(Proposal& proposal, const string& dataString)
{    
    return proposal.ParseFromString(dataString);
}

bool npl_serialize_to_string(NPL& npl, string* output)
{
     if(npl.has_data() 
        && npl.has_lcl())

    return npl.SerializeToString(output);

    else
        return false;
}

bool npl_parse_from_string(NPL& npl, const string& dataString)
{
    return npl.ParseFromString(dataString);
}

}