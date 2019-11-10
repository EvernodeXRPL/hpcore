#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "../fbschema/p2pmsg_container_generated.h"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../sock/socket_message.hpp"
#include "../sock/socket_session.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"

namespace p2pmsg = fbschema::p2pmsg;

namespace p2p
{

// The set of recent peer message hashes used for duplicate detection.
util::rollover_hashset recent_peermsg_hashes(200);

/**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
void peer_session_handler::on_connect(sock::socket_session<peer_outbound_message> *session)
{
    if (!session->flags[sock::SESSION_FLAG::INBOUND])
    {
        std::lock_guard<std::mutex> lock(ctx.peer_connections_mutex);
        ctx.peer_connections.try_emplace(session->uniqueid, session);
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
    const flatbuffers::uoffset_t content_size = container_content->size();

    const p2pmsg::Content *content;
    if (p2pmsg::validate_and_extract_content(&content, content_ptr, content_size) != 0)
        return;

    if (!recent_peermsg_hashes.try_emplace(crypto::get_hash(message)))
    {
        session->increment_metric(sock::SESSION_THRESHOLDS::MAX_DUPMSGS_PER_MINUTE, 1);
        LOG_DBG << "Duplicate peer message.";
        return;
    }

    const p2pmsg::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

    if (content_message_type == p2pmsg::Message_Proposal_Message) //message is a proposal message
    {
        // We only trust proposals coming from trusted peers.
        if (p2pmsg::validate_container_trust(container) != 0)
        {
            session->increment_metric(sock::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
            LOG_DBG << "Proposal rejected due to trust failure.";
            return;
        }

        std::lock_guard<std::mutex> lock(ctx.collected_msgs.proposals_mutex); // Insert proposal with lock.

        ctx.collected_msgs.proposals.push_back(
            p2pmsg::create_proposal_from_msg(*content->message_as_Proposal_Message(), container->pubkey(), container->timestamp()));
    }
    else if (content_message_type == p2pmsg::Message_NonUnl_Proposal_Message) //message is a non-unl proposal message
    {
        std::lock_guard<std::mutex> lock(ctx.collected_msgs.nonunl_proposals_mutex); // Insert non-unl proposal with lock.

        ctx.collected_msgs.nonunl_proposals.push_back(
            p2pmsg::create_nonunl_proposal_from_msg(*content->message_as_NonUnl_Proposal_Message(), container->timestamp()));
    }
    else if (content_message_type == p2pmsg::Message_Npl_Message) //message is a NPL message
    {
        const p2pmsg::Npl_Message *npl = content->message_as_Npl_Message();
        // execute npl logic here.
        //broadcast message.
    }
    else
    {
        session->increment_metric(sock::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
        LOG_DBG << "Received invalid message type from peer";
    }
}

//peer session on message callback method
void peer_session_handler::on_close(sock::socket_session<peer_outbound_message> *session)
{
    {
        std::lock_guard<std::mutex> lock(ctx.peer_connections_mutex);
        ctx.peer_connections.erase(session->uniqueid);
    }
    LOG_DBG << "Peer disonnected: " << session->uniqueid;
}

} // namespace p2p