#include <iostream>
#include "message.pb.h"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{

/**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
void peer_session_handler::on_connect(sock::socket_session *session)
{
    std::cout << "Sending message" << std::endl;
    auto const message = std::make_shared<std::string const>("Connected successfully");
    session->send(message);
    //todo:check connected peer is in peer list.
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session *session, const std::string &message)
{
    std::cout << "on-message : " << message << std::endl;
    //session->send(std::make_shared<std::string>(message));
    
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    Message container_message;

    if (p2p::message_parse_from_string(container_message, message))
    {
        if (p2p::validate_peer_message(container_message, message))
        {
            auto message_type = container_message.type();

            if (message_type == p2p::Message::PROPOSAL)
            {
                p2p::Proposal proposal;
                proposal_parse_from_string(proposal, container_message.content());

                std::string prop_name;
                prop_name.reserve(container_message.publickey().size() + 1 + sizeof(proposal.stage()));
                prop_name += container_message.publickey();
                prop_name += '-';
                prop_name += proposal.stage();

                //put it into propsal message map
                consensus_ctx.proposals.try_emplace(prop_name, proposal);
                //broadcast it
            }
            else if (message_type == p2p::Message::NPL)
            {
                p2p::NPL npl;
                npl_parse_from_string(npl, container_message.content());

                //put it into npl list
                p2p::peer_ctx.npl_messages.push_back(npl);
                //broadcast it
            }
            else
            {
            }
        }
    }
    else
    {
        //bad message
    }
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session *session)
{
    std::cout << "on_close";
}

} // namespace p2p