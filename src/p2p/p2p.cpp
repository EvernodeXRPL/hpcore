#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>

#include "message.pb.h"
#include "p2p.hpp"
#include "../conf.hpp"

using namespace std;

namespace p2p
{

namespace protobuf = google::protobuf;

void set_message(Message &message, int timestamp, const string &version, const string &publicKey, const string &signature, p2p::Message::Messagetype type, const string &content)
{
    message.set_version(version);
    message.set_timestamp(timestamp);
    message.set_publickey(publicKey);
    message.set_signature(signature);
    message.set_type(type);
    message.set_content(content);
}

bool message_serialize_to_string(Message &message, string &output)
{
    //check all fields are set in message
    if (message.has_publickey() && message.has_signature() && message.has_timestamp() && message.has_type() && message.has_version() && message.has_content())

        return message.SerializeToString(&output);

    else
        return false;
}

bool message_parse_from_string(Message &message, const string &dataString)
{
    return message.ParseFromString(dataString);
}

void set_proposal_inputs(Proposal &proposal, const vector<string> &inputs)
{
    protobuf::RepeatedPtrField<std::string>* proposal_inputs = proposal.mutable_outputs();
    proposal_inputs-> Reserve(inputs.size());
    *proposal_inputs = {inputs.begin(), inputs.end()};
}

void set_proposal_outputs(Proposal &proposal, const vector<string> &outputs)
{
    google::protobuf::RepeatedPtrField<std::string>* proposal_outputs = proposal.mutable_outputs();
    proposal_outputs-> Reserve(outputs.size());
    *proposal_outputs = {outputs.begin(), outputs.end()};
}

void set_proposal_connections(Proposal &proposal, const vector<string> &connections)
{
    protobuf::RepeatedPtrField<std::string>* proposal_connections = proposal.mutable_inputs();
    proposal_connections ->  Reserve(connections.size());
    (*proposal_connections) = {connections.begin(), connections.end()};
}

void set_state_patch(State &state, const map<string, string>& patches)
{
    *state.mutable_patch() = {patches.begin(), patches.end()};
}

bool proposal_serialize_to_string(Proposal &proposal, string &output)
{
    //check all fields are set in the proposal
    if (proposal.has_stage() && proposal.has_lcl() && proposal.has_state() && proposal.has_time() && (proposal.inputs_size() == 0) && (proposal.outputs_size() == 0))
        return proposal.SerializeToString(&output);

    else
        return false;
}

bool proposal_parse_from_string(Proposal &proposal, const string &dataString)
{
    return proposal.ParseFromString(dataString);
}

bool npl_serialize_to_string(NPL &npl, string &output)
{
    //check all fields are set in the proposal
    //not sure npl messages need both data or lcl have to be set.
    //may be only one needed. need to deal with this when processing npl messages
    if (npl.has_data() && npl.has_lcl())

        return npl.SerializeToString(&output);

    else
        return false;
}

bool npl_parse_from_string(NPL &npl, const string &dataString)
{
    return npl.ParseFromString(dataString);
}

} // namespace p2p