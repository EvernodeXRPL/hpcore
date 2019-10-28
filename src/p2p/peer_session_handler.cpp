#include <iostream>
#include <flatbuffers/flatbuffers.h>
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"
#include "peer_message_handler.hpp"
#include "message_content_generated.h"
#include "message_container_generated.h"

namespace p2p
{

peer_outbound_message::peer_outbound_message(
    std::shared_ptr<flatbuffers::FlatBufferBuilder> _fbbuilder_ptr)
{
    fbbuilder_ptr = _fbbuilder_ptr;
}

// Returns a reference to the flatbuffer builder object.
flatbuffers::FlatBufferBuilder &peer_outbound_message::builder()
{
    return *fbbuilder_ptr;
}

// Returns a reference to the data buffer that must be written to the socket.
std::string_view peer_outbound_message::buffer()
{
    return std::string_view(
        reinterpret_cast<const char *>((*fbbuilder_ptr).GetBufferPointer()),
        (*fbbuilder_ptr).GetSize());
}

/**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
void peer_session_handler::on_connect(sock::socket_session<peer_outbound_message> *session)
{
    if (!session->flags[util::SESSION_FLAG::INBOUND])
    {
        // We init the session unique id to associate with the challenge.
        session->init_uniqueid();
        {
            std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
            peer_connections.insert(std::make_pair(session->uniqueid, session));
        }
        LOG_DBG << "Adding peer to list: " << session->uniqueid;
    }
    else
    {
        // todo: set container builder defualt builder size to combination of serialized content length + signature length(which is fixed)
        // peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));

        // proposal p;
        // create_msg_from_proposal(msg.builder(), p);
        // session->send(msg);
    }
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session<peer_outbound_message> *session, std::string_view message)
{
    const Container *container;
    if (validate_and_extract_container(&container, message) != 0)
        return;

    //Get serialised message content.
    const flatbuffers::Vector<uint8_t> *container_content = container->content();

    //Accessing message content and size.
    const uint8_t *content_ptr = container_content->Data();
    flatbuffers::uoffset_t content_size = container_content->size();

    const Content *content;
    if (validate_and_extract_content(&content, content_ptr, content_size) != 0)
        return;

    p2p::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

    if (content_message_type == Message_Proposal_Message) //message is a proposal message
    {
        // We only trust proposals coming from trusted peers.
        if (validate_container_trust(container) != 0)
        {
            LOG_DBG << "Proposal rejected due to trust failure.";
            return;
        }

        std::lock_guard<std::mutex> lock(collected_msgs.proposals_mutex); // Insert proposal with lock.

        collected_msgs.proposals.push_back(
            create_proposal_from_msg(*content->message_as_Proposal_Message(), container->pubkey()));
    }
    else if (content_message_type == Message_Npl_Message) //message is a NPL message
    {
        const Npl_Message *npl = content->message_as_Npl_Message();
        // execute npl logic here.
        //broadcast message.
    }
    else
    {
        //warn received invalid message from peer.
        LOG_DBG << "Received invalid message type from peer";
        //TODO: remove/penalize node who sent the message.
    }
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session<peer_outbound_message> *session)
{
    {
        std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
        peer_connections.erase(session->uniqueid);
    }
    LOG_DBG << "Peer disonnected: " << session->uniqueid;
}

} // namespace p2p