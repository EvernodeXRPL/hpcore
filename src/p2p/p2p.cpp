#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>

#include "../sock/socket_server.hpp"
#include "../sock/socket_client.hpp"
#include "peer_session_handler.hpp"
#include "message.pb.h"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../usr/usr.hpp"
#include "p2p.hpp"

namespace p2p
{

namespace protobuf = google::protobuf;
peer_context peer_ctx;
consensus_context consensus_ctx;
peer_session_handler peer_session_manager;

//set all fields of given message.
void set_message(Message &message, const int timestamp, const std::string &version, const std::string &publicKey, const std::string &signature, p2p::Message::Messagetype type, const std::string &content)
{
    message.set_version(version);
    message.set_timestamp(timestamp);
    message.set_publickey(publicKey);
    message.set_signature(signature);
    message.set_type(type);
    message.set_content(content);
}

// Serialize the message and store it in the given string.  All message
// fields must be set. Consensus rounds need all fileds.
bool message_serialize_to_string(Message &message, std::string &output)
{
    //check all fields are set in message
    if (message.has_publickey() && message.has_signature() && message.has_timestamp() && message.has_type() && message.has_version() && message.has_content())

        return message.SerializeToString(&output);

    else
        return false;
}

// Parsing the message from binary message string to given message.
bool message_parse_from_string(Message &message, const std::string &dataString)
{
    return message.ParseFromString(dataString);
}

//Set proposal inputs from given string vector.
void set_proposal_inputs(Proposal &proposal, const std::vector<std::string> &inputs)
{
    protobuf::RepeatedPtrField<std::string> *proposal_inputs = proposal.mutable_outputs();
    proposal_inputs->Reserve(inputs.size());
    *proposal_inputs = {inputs.begin(), inputs.end()};
}

//Set proposal outputs from given string vector.
void set_proposal_outputs(Proposal &proposal, const std::vector<std::string> &outputs)
{
    google::protobuf::RepeatedPtrField<std::string> *proposal_outputs = proposal.mutable_outputs();
    proposal_outputs->Reserve(outputs.size());
    *proposal_outputs = {outputs.begin(), outputs.end()};
}

//Set proposal connections from given string vector.
void set_proposal_connections(Proposal &proposal, const std::vector<std::string> &connections)
{
    protobuf::RepeatedPtrField<std::string> *proposal_connections = proposal.mutable_inputs();
    proposal_connections->Reserve(connections.size());
    (*proposal_connections) = {connections.begin(), connections.end()};
}

//Set proposal state patches from given map of patches.
void set_state_patch(State &state, const std::map<std::string, std::string> &patches)
{
    *state.mutable_patch() = {patches.begin(), patches.end()};
}

// Serialize the proposal message and store it in the given string.  All propsal message
// fields must be set. Consensus rounds need all fileds.
bool proposal_serialize_to_string(Proposal &proposal, std::string &output)
{
    //check all fields are set in the proposal
    if (proposal.has_stage() && proposal.has_lcl() && proposal.has_state() && proposal.has_time() && (proposal.inputs_size() == 0) && (proposal.outputs_size() == 0))
        return proposal.SerializeToString(&output);

    else
        return false;
}

// Parsing the proposal message from binary string to given message.
bool proposal_parse_from_string(Proposal &proposal, const std::string &dataString)
{
    return proposal.ParseFromString(dataString);
}

// Serialize the npl message and store it in the given string.  All npl message
// fields must be set.
bool npl_serialize_to_string(NPL &npl, std::string &output)
{
    //check all fields are set in the proposal
    //not sure npl messages need both data or lcl have to be set.
    //may be only one needed. need to deal with this when processing npl messages
    if (npl.has_data() && npl.has_lcl())

        return npl.SerializeToString(&output);

    else
        return false;
}

// Parsing the npl message from binary string to given message.
bool npl_parse_from_string(NPL &npl, const std::string &dataString)
{
    return npl.ParseFromString(dataString);
}

void open_listen()
{

    auto address = net::ip::make_address("0.0.0.0");
    net::io_context ioc;

    // std::make_shared<sock::socket_server>(
    //     ioc,
    //     tcp::endpoint{address, 22860},
    //     peer_session_manager)
    //     ->run();

    std::make_shared<sock::socket_client>(ioc, peer_session_manager)->run((conf::cfg.listenip).c_str(), "22860");

    std::thread run_thread([&] { ioc.run(); });
    int t;
    std::cin >> t;
}

bool validate_peer_message(const p2p::Message &peer_message, const std::string &message)
{
    std::time_t timestamp = std::time(nullptr);
    //todo:check pubkey in unl list. need to change unl list to a map.

    //check message timestamp < timestamp now - 4* round time
    if (peer_message.timestamp() < (timestamp - conf::cfg.roundtime * 4))
    {
        std::cout << "recieved message from peer is old" << std::endl;
        return false;
    }

    //get message hash and see wheteher message is already recieved -> abandon
    auto messageHash = crypto::sha_512_hash(message, "PEERMSG", 7);

    if (peer_ctx.recent_peer_msghash.count(messageHash) == 0)
    {
        peer_ctx.recent_peer_msghash.try_emplace(messageHash, timestamp);
    }
    else
    {
        return false;
    }

    //check signature
    //todo:move to initial part.

    return true;
}

void consensus()
{
    std::time_t timestamp = std::time(nullptr);
    p2p::Proposal proposal;

    switch (consensus_ctx.stage)
    {

    case 0: // in stage 0 we create a novel proposal and broadcast it
    {
        // clear out the old stage 3 proposals and any previous proposals made by us
        // todo: check the state of these to ensure we're running consensus ledger
        for (const auto &p : consensus_ctx.proposals)
        {
            auto propsal = p.second;
            if (propsal.stage() == 3 || conf::cfg.pubkeyb64 == "propsal pubkey")
                consensus_ctx.proposals.erase(p.first);
        }

        for (const auto &user : usr::users)
        {
            // add all the connections we host
            proposal.add_connections(user.second.pubkeyb64);

            // todo:add all their pending messages
        }

        // todo:propose outputs from previous round if any
        // todo: set propsal states

        consensus_ctx.novel_proposal_time = timestamp;
        //proposal.time() = static_cast<int> (timestamp); time_t is long int

        //broadcast_to_peers(sign_peer_message(proposal).signed)
    }
    case 1:
    case 2:
    case 3:
    {
    }
    }
}

} // namespace p2p