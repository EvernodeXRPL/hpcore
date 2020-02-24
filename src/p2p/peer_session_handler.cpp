#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "../fbschema/p2pmsg_container_generated.h"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/common_helpers.hpp"
#include "../comm/comm_session.hpp"
#include "../comm/comm_client.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"
#include "../cons/ledger_handler.hpp"
#include "../cons/state_handler.hpp"
#include "../cons/cons.hpp"

namespace p2pmsg = fbschema::p2pmsg;

namespace p2p
{

// The set of recent peer message hashes used for duplicate detection.
util::rollover_hashset recent_peermsg_hashes(200);

/**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
void peer_session_handler::on_connect(comm::comm_session &session) const
{
    if (session.is_inbound)
    {
        // Limit max number of inbound connections.
        if (conf::cfg.peermaxcons > 0 && ctx.peer_connections.size() >= conf::cfg.peermaxcons)
        {
            session.close();
            LOG_DBG << "Max peer connections reached. Dropped connection " << session.uniqueid;
            return;
        }
    }

    // Send our peer id.
    flatbuffers::FlatBufferBuilder fbuf(1024);
    p2pmsg::create_msg_from_peerid(fbuf, conf::cfg.self_peerid);
    std::string_view msg = std::string_view(
        reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
    session.send(msg);
}

//peer session on message callback method
//validate and handle each type of peer messages.
void peer_session_handler::on_message(comm::comm_session &session, std::string_view message) const
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
        session.increment_metric(comm::SESSION_THRESHOLDS::MAX_DUPMSGS_PER_MINUTE, 1);
        LOG_DBG << "Duplicate peer message.";
        return;
    }

    const p2pmsg::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

    if (content_message_type == p2pmsg::Message_PeerId_Notify_Message) // message is a peer id announcement
    {
        if (session.flags[comm::SESSION_FLAG::PEERID_RESOLVED])
            return; // Peer ID already resolved. Ignore.

        const std::string peerid = std::string(p2pmsg::get_peerid_from_msg(*content->message_as_PeerId_Notify_Message()));

        int res = peerid.compare(conf::cfg.self_peerid);

        // If peerid is same as our (self) peerid, then this is the loopback connection to ourselves.
        // Hence we must keep the connection.
        // If peerid is greater than our id, then we should give priority to any existing inbound connection
        // from the same peer and drop the outbound connection.
        // If peerid is lower than our id, then we should give priority to any existing outbound connection
        // from the same peer and drop the inbound connection.

        conf::ip_port_pair known_ipport;

        // Check for any existing connection to the same peer.
        const auto iter = p2p::ctx.peer_connections.find(peerid);
        if (res != 0 && iter != p2p::ctx.peer_connections.end())
        {
            comm::comm_session &ex_session = iter->second;
            comm::comm_session &victim =
                ((res > 0 && ex_session.is_inbound) ||
                 (res < 0 && !ex_session.is_inbound))
                    ? session
                    : ex_session;

            victim.close();
            // If we happen to replace a known peer session, transfer those details to the new session.
            victim.known_ipport.swap(known_ipport);
        }

        // If the new session is still active then that means it should remain.
        if (session.state == comm::SESSION_STATE::ACTIVE)
        {
            session.uniqueid = peerid;
            session.flags.set(comm::SESSION_FLAG::PEERID_RESOLVED);
            session.known_ipport.swap(known_ipport);

            p2p::ctx.peer_connections.try_emplace(session.uniqueid, session);
        }
    }
    else if (content_message_type == p2pmsg::Message_Proposal_Message) // message is a proposal message
    {
        // We only trust proposals coming from trusted peers.
        if (p2pmsg::validate_container_trust(container) != 0)
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
            LOG_DBG << "Proposal rejected due to trust failure.";
            return;
        }

        std::lock_guard<std::mutex> lock(ctx.collected_msgs.proposals_mutex); // Insert proposal with lock.

        ctx.collected_msgs.proposals.push_back(
            p2pmsg::create_proposal_from_msg(*content->message_as_Proposal_Message(), container->pubkey(), container->timestamp(), container->lcl()));
    }
    else if (content_message_type == p2pmsg::Message_NonUnl_Proposal_Message) //message is a non-unl proposal message
    {
        std::lock_guard<std::mutex> lock(ctx.collected_msgs.nonunl_proposals_mutex); // Insert non-unl proposal with lock.

        ctx.collected_msgs.nonunl_proposals.push_back(
            p2pmsg::create_nonunl_proposal_from_msg(*content->message_as_NonUnl_Proposal_Message(), container->timestamp()));
    }
    else if (content_message_type == p2pmsg::Message_Npl_Message) //message is a NPL message
    {
        if (p2pmsg::validate_container_trust(container) != 0)
        {
            LOG_DBG << "NPL message rejected due to trust failure.";
            return;
        }

        std::lock_guard<std::mutex> lock(ctx.collected_msgs.npl_messages_mutex); // Insert npl message with lock.

        // Npl messages are added to the npl message array as it is without deserealizing the content. The same content will be passed down
        // to the contract as input in a binary format
        const uint8_t *container_buf_ptr = reinterpret_cast<const uint8_t *>(message.data());
        const size_t container_buf_size = message.length();
        const std::string npl_message(reinterpret_cast<const char *>(container_buf_ptr), container_buf_size);
        ctx.collected_msgs.npl_messages.push_back(std::move(npl_message));
    }
    else if (content_message_type == p2pmsg::Message_State_Request_Message)
    {
        if (p2pmsg::validate_container_trust(container) != 0)
        {
            LOG_DBG << "State request message rejected due to trust failure.";
            return;
        }

        const p2p::state_request sr = p2pmsg::create_state_request_from_msg(*content->message_as_State_Request_Message());
        flatbuffers::FlatBufferBuilder fbuf(1024);

        if (cons::create_state_response(fbuf, sr) == 0)
        {
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
            session.send(msg);
        }
    }
    else if (content_message_type == p2pmsg::Message_State_Response_Message)
    {
        std::lock_guard<std::mutex> lock(ctx.collected_msgs.state_response_mutex); // Insert state_response with lock.
        std::string response(reinterpret_cast<const char *>(content_ptr), content_size);
        ctx.collected_msgs.state_response.push_back(std::move(response));
    }
    else if (content_message_type == p2pmsg::Message_History_Request_Message) //message is a lcl history request message
    {
        const p2p::history_request hr = p2pmsg::create_history_request_from_msg(*content->message_as_History_Request_Message());
        //first check node has the required lcl available. -> if so send lcl history accordingly.
        const bool req_lcl_avail = cons::check_required_lcl_availability(hr);
        if (req_lcl_avail)
        {
            flatbuffers::FlatBufferBuilder fbuf(1024);
            p2pmsg::create_msg_from_history_response(fbuf, cons::retrieve_ledger_history(hr));
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());

            session.send(msg);
        }
    }
    else if (content_message_type == p2pmsg::Message_History_Response_Message) //message is a lcl history response message
    {
        cons::handle_ledger_history_response(
            p2pmsg::create_history_response_from_msg(*content->message_as_History_Response_Message()));
    }
    else
    {
        session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
        LOG_DBG << "Received invalid message type from peer";
    }
}

//peer session on message callback method
void peer_session_handler::on_close(const comm::comm_session &session) const
{
    //std::lock_guard<std::mutex> lock(ctx.peer_connections_mutex);
    ctx.peer_connections.erase(session.uniqueid);
    LOG_DBG << "Peer session closed: " << session.uniqueid << (session.is_self ? "(self)" : "");
}

} // namespace p2p