#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "../fbschema/p2pmsg_container_generated.h"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/common_helpers.hpp"
#include "../sock/socket_message.hpp"
#include "../sock/socket_session.hpp"
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
void peer_session_handler::on_connect(sock::socket_session<peer_outbound_message> *session)
{
    if (session->flags[sock::SESSION_FLAG::INBOUND])
    {
        // Limit max number of inbound connections.
        if (conf::cfg.peermaxcons > 0 && ctx.peer_connections.size() >= conf::cfg.peermaxcons)
        {
            session->close();
            LOG_DBG << "Max peer connections reached. Dropped connection " << session->uniqueid;
        }
    }
    else
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
        std::cout << "Receieved state request"<<std::endl;
        std::cout << "State request lcl :"<<fbschema::flatbuff_bytes_to_sv(container->lcl()) <<std::endl;
        std::cout << "my lcl :"<<cons::ctx.lcl <<std::endl;

        if (fbschema::flatbuff_bytes_to_sv(container->lcl()) == cons::ctx.lcl && cons::ctx.curr_hash_state == cons::ctx.cache.rbegin()->second.state)
        {
            std::cout << "******************sending state response*************************" << std::endl;

            const p2p::state_request sr = p2pmsg::create_state_request_from_msg(*content->message_as_State_Request_Message());
            session->send(cons::send_state_response(sr));
        }
        else
        {
            // todo: send an error response
            std::cout << "Cannot send state response. My state incorrect." << std::endl;
        }
    }
    else if (content_message_type == p2pmsg::Message_State_Response_Message)
    {
        std::cout << "Receieved state response" << std::endl;
        std::lock_guard<std::mutex> lock(ctx.collected_msgs.state_response_mutex); // Insert state_response with lock.
        std::string response(reinterpret_cast<const char *>(content_ptr), content_size);
        ctx.collected_msgs.state_response.push_back(std::move(response));
    }
    else if (content_message_type == p2pmsg::Message_History_Request_Message) //message is a lcl history request message
    {
        LOG_DBG << "Received history request message type from peer.";

        const p2p::history_request hr = p2pmsg::create_history_request_from_msg(*content->message_as_History_Request_Message());
        //first check node has the required lcl available. -> if so send lcl history accordingly.
        bool req_lcl_avail = cons::check_required_lcl_availability(hr);
        if (req_lcl_avail > 0)
        {
            p2p::peer_outbound_message hr_msg = cons::send_ledger_history(hr);
            session->send(hr_msg);
        }
    }
    else if (content_message_type == p2pmsg::Message_History_Response_Message) //message is a lcl history response message
    {
        LOG_DBG << "Received history response message type from peer.";

        cons::handle_ledger_history_response(
            p2pmsg::create_history_response_from_msg(*content->message_as_History_Response_Message()));
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