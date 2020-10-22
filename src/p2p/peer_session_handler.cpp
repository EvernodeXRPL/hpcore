#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../consensus.hpp"
#include "../crypto.hpp"
#include "../util.hpp"
#include "../hplog.hpp"
#include "../msg/fbuf/p2pmsg_container_generated.h"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../comm/comm_session.hpp"
#include "p2p.hpp"
#include "peer_session_handler.hpp"
#include "../state/state_sync.hpp"
#include "../ledger.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace p2p
{

    // The set of recent peer message hashes used for duplicate detection.
    util::rollover_hashset recent_peermsg_hashes(200);

    /**
 * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
 */
    int peer_session_handler::on_connect(comm::comm_session &session) const
    {
        if (session.is_inbound)
        {
            // Limit max number of inbound connections.
            if (conf::cfg.peermaxcons > 0 && ctx.peer_connections.size() >= conf::cfg.peermaxcons)
            {
                LOG_DEBUG << "Max peer connections reached. Dropped connection " << session.uniqueid.substr(0, 10);
                return -1;
            }
        }

        // Send peer challenge.
        flatbuffers::FlatBufferBuilder fbuf(1024);
        p2pmsg::create_msg_from_peer_challenge(fbuf, session.issued_challenge);
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
        session.send(msg);
        session.challenge_status = comm::CHALLENGE_ISSUED;
        return 0;
    }

    //peer session on message callback method
    //validate and handle each type of peer messages.
    int peer_session_handler::on_message(comm::comm_session &session, std::string_view message) const
    {
        const p2pmsg::Container *container;
        if (p2pmsg::validate_and_extract_container(&container, message) != 0)
            return 0;

        //Get serialised message content.
        const flatbuffers::Vector<uint8_t> *container_content = container->content();

        //Accessing message content and size.
        const uint8_t *content_ptr = container_content->Data();
        const flatbuffers::uoffset_t content_size = container_content->size();

        const p2pmsg::Content *content;
        if (p2pmsg::validate_and_extract_content(&content, content_ptr, content_size) != 0)
            return 0;

        if (!recent_peermsg_hashes.try_emplace(crypto::get_hash(message)))
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_DUPMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Duplicate peer message. " << session.uniqueid.substr(0, 10);
            return 0;
        }

        const p2pmsg::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc
        // Check whether the message is qualified for forwarding.
        if (p2p::validate_for_peer_msg_forwarding(session, container, content_message_type))
        {
            // Forward message to peers.
            p2p::broadcast_message(message, false, true, &session);
        }

        if (content_message_type == p2pmsg::Message_Peer_Challenge_Message) // message is a peer challenge announcement
        {
            // Sending the challenge response to the respected peer.
            const std::string challenge = std::string(p2pmsg::get_peer_challenge_from_msg(*content->message_as_Peer_Challenge_Message()));
            flatbuffers::FlatBufferBuilder fbuf(1024);
            p2pmsg::create_peer_challenge_response_from_challenge(fbuf, challenge);
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
            return session.send(msg);
        }

        if (content_message_type == p2pmsg::Message_Peer_Challenge_Response_Message) // message is a peer challenge response
        {
            // Ignore if challenge is already resolved.
            if (session.challenge_status == comm::CHALLENGE_ISSUED)
            {
                const p2p::peer_challenge_response challenge_resp = p2pmsg::create_peer_challenge_response_from_msg(*content->message_as_Peer_Challenge_Response_Message(), container->pubkey());
                return p2p::resolve_peer_challenge(session, challenge_resp);
            }
        }

        if (session.challenge_status != comm::CHALLENGE_VERIFIED)
        {
            LOG_DEBUG << "Cannot accept messages. Peer challenge unresolved. " << session.uniqueid.substr(0, 10);
            return 0;
        }

        if (content_message_type == p2pmsg::Message_Proposal_Message) // message is a proposal message
        {
            // We only trust proposals coming from trusted peers.
            if (p2pmsg::validate_container_trust(container) != 0)
            {
                session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "Proposal rejected due to trust failure. " << session.uniqueid.substr(0, 10);
                return 0;
            }

            std::scoped_lock<std::mutex> lock(ctx.collected_msgs.proposals_mutex); // Insert proposal with lock.

            ctx.collected_msgs.proposals.push_back(
                p2pmsg::create_proposal_from_msg(*content->message_as_Proposal_Message(), container->pubkey(), container->timestamp(), container->lcl()));
        }
        else if (content_message_type == p2pmsg::Message_NonUnl_Proposal_Message) //message is a non-unl proposal message
        {
            std::scoped_lock<std::mutex> lock(ctx.collected_msgs.nonunl_proposals_mutex); // Insert non-unl proposal with lock.

            ctx.collected_msgs.nonunl_proposals.push_back(
                p2pmsg::create_nonunl_proposal_from_msg(*content->message_as_NonUnl_Proposal_Message(), container->timestamp()));
        }
        else if (content_message_type == p2pmsg::Message_Npl_Message) //message is a NPL message
        {
            if (p2pmsg::validate_container_trust(container) != 0)
            {
                session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "NPL message rejected due to trust failure. " << session.uniqueid.substr(0, 10);
                return 0;
            }

            const p2pmsg::Npl_Message *npl_p2p_msg = content->message_as_Npl_Message();
            npl_message msg;
            msg.data = msg::fbuf::flatbuff_bytes_to_sv(npl_p2p_msg->data());
            msg.pubkey = msg::fbuf::flatbuff_bytes_to_sv(container->pubkey());
            msg.lcl = msg::fbuf::flatbuff_bytes_to_sv(container->lcl());

            if (!consensus::push_npl_message(msg))
            {
                LOG_DEBUG << "NPL message enqueue failure. " << session.uniqueid.substr(0, 10);
            }
        }
        else if (content_message_type == p2pmsg::Message_P2P_Forwarding_Announcement_Message) // This message is a message forwarding requirement announcement message.
        {
            const p2pmsg::P2P_Forwarding_Announcement_Message *announcement_msg = content->message_as_P2P_Forwarding_Announcement_Message();
            session.need_p2p_msg_forwarding = announcement_msg->is_required();
            if (announcement_msg->is_required())
            {
                LOG_ERROR << "Message forwarding is requested by " << session.uniqueid;
            }
            else
            {
                LOG_ERROR << "Message forwarding is end request by " << session.uniqueid;
            }
        }
        else if (content_message_type == p2pmsg::Message_State_Request_Message)
        {

            // Insert request with lock.
            std::scoped_lock<std::mutex> lock(ctx.collected_msgs.state_requests_mutex);
            std::string state_request_msg(reinterpret_cast<const char *>(content_ptr), content_size);
            ctx.collected_msgs.state_requests.push_back(std::make_pair(session.uniqueid, std::move(state_request_msg)));
        }
        else if (content_message_type == p2pmsg::Message_State_Response_Message)
        {
            if (state_sync::ctx.is_syncing) // Only accept state responses if state is syncing.
            {
                // Insert state_response with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.state_responses_mutex);
                std::string response(reinterpret_cast<const char *>(content_ptr), content_size);
                ctx.collected_msgs.state_responses.push_back(std::move(response));
            }
        }
        else if (content_message_type == p2pmsg::Message_History_Request_Message) //message is a lcl history request message
        {
            const p2p::history_request hr = p2pmsg::create_history_request_from_msg(*content->message_as_History_Request_Message());
            std::scoped_lock<std::mutex> lock(ledger::sync_ctx.list_mutex);
            ledger::sync_ctx.collected_history_requests.push_back(std::make_pair(session.uniqueid, std::move(hr)));
        }
        else if (content_message_type == p2pmsg::Message_History_Response_Message) //message is a lcl history response message
        {
            const p2p::history_response hr = p2pmsg::create_history_response_from_msg(*content->message_as_History_Response_Message());
            std::scoped_lock<std::mutex> lock(ledger::sync_ctx.list_mutex);
            ledger::sync_ctx.collected_history_responses.push_back(std::move(hr));
        }
        else
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Received invalid peer message type. " << session.uniqueid.substr(0, 10);
        }
        return 0;
    }

    //peer session on message callback method
    void peer_session_handler::on_close(const comm::comm_session &session) const
    {
        // Erase the corresponding uniqueid peer connection if it's this session.
        std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);
        const auto itr = ctx.peer_connections.find(session.uniqueid);
        if (itr != ctx.peer_connections.end() && itr->second == &session)
            ctx.peer_connections.erase(itr);
    }

} // namespace p2p