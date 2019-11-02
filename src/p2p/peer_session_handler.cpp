#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "../fbschema/p2pmsg_container_generated.h"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../sock/socket_message.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"

namespace p2pmsg = fbschema::p2pmsg;

namespace p2p
{

/**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
void peer_session_handler::on_connect(sock::socket_session<peer_outbound_message> *session)
{
    if (!session->flags[util::SESSION_FLAG::INBOUND])
    {
        // We init the session unique id to associate with the peer.
        session->init_uniqueid();
        {
            std::lock_guard<std::mutex> lock(p2p::peer_connections_mutex);
            peer_connections.insert(std::make_pair(session->uniqueid, session));
        }
        LOG_DBG << "Adding peer to list: " << session->uniqueid;
    }
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(sock::socket_session<peer_outbound_message> *session, std::string_view message)
{
    const p2pmsg::Container *container;
    if (p2pmsg::validate_and_extract_container(&container, message) != 0)
        return;

    //Get serialised message content.
    const flatbuffers::Vector<uint8_t> *container_content = container->content();

    //Accessing message content and size.
    const uint8_t *content_ptr = container_content->Data();
    flatbuffers::uoffset_t content_size = container_content->size();

    const p2pmsg::Content *content;
    if (p2pmsg::validate_and_extract_content(&content, content_ptr, content_size) != 0)
        return;

    if (is_message_duplicate(message))
        return;

    p2pmsg::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

    if (content_message_type == p2pmsg::Message_Proposal_Message) //message is a proposal message
    {
        // We only trust proposals coming from trusted peers.
        if (p2pmsg::validate_container_trust(container) != 0)
        {
            LOG_DBG << "Proposal rejected due to trust failure.";
            return;
        }

        std::lock_guard<std::mutex> lock(collected_msgs.proposals_mutex); // Insert proposal with lock.

        collected_msgs.proposals.push_back(
            p2pmsg::create_proposal_from_msg(*content->message_as_Proposal_Message(), container->pubkey(), container->timestamp()));
    }
    else if (content_message_type == p2pmsg::Message_Npl_Message) //message is a NPL message
    {
        const p2pmsg::Npl_Message *npl = content->message_as_Npl_Message();
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