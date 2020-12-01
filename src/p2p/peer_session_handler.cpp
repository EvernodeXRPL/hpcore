#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../consensus.hpp"
#include "../crypto.hpp"
#include "../util/util.hpp"
#include "../util/rollover_hashset.hpp"
#include "../hplog.hpp"
#include "../msg/fbuf/p2pmsg_container_generated.h"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../msg/fbuf/p2pmsg_helpers.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../state/state_sync.hpp"
#include "../ledger.hpp"
#include "peer_comm_session.hpp"
#include "p2p.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace p2p
{
    // The set of recent peer message hashes used for duplicate detection.
    util::rollover_hashset recent_peermsg_hashes(200);

    /**
     * This gets hit every time a peer connects to HP via the peer port (configured in contract config).
     * @param session connected session.
     * @return returns 0 if connection is successful and peer challenge is sent otherwise, -1.
     */
    int handle_peer_connect(p2p::peer_comm_session &session)
    {
        // Skip new inbound connection if max inbound connection cap is reached.
        if (session.is_inbound && get_available_capacity() == 0)
        {
            LOG_DEBUG << "Max peer connection cap reached. Rejecting new peer connection [" << session.display_name() << "]";
            return -1;
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

    /**
     * Peer session on message callback method. Validate and handle each type of peer messages.
     * @return 0 on normal execution. -1 when session needs to be closed as a result of message handling.
     */
    int handle_peer_message(p2p::peer_comm_session &session, std::string_view message)
    {
        // Adding message size to peer message characters(bytes) per minute counter.
        session.increment_metric(comm::SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, message.size());

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
            LOG_DEBUG << "Duplicate peer message. " << session.display_name();
            return 0;
        }

        const p2pmsg::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

        // Check whether the message is qualified for message forwarding.
        if (p2p::validate_for_peer_msg_forwarding(session, container, content_message_type))
        {
            // Npl messages are forwarded only to trusted peers.
            const bool only_to_trusted_peers = content_message_type == p2pmsg::Message_Npl_Message;
            if (session.need_consensus_msg_forwarding)
            {
                // Forward messages received by weakly connected nodes to other peers.
                p2p::broadcast_message(message, false, false, only_to_trusted_peers, &session);
            }
            else
            {
                // Forward message received from other nodes to weakly connected peers.
                p2p::broadcast_message(message, false, true, only_to_trusted_peers, &session);
            }
        }

        if (content_message_type == p2pmsg::Message_Peer_Challenge_Message) // message is a peer challenge announcement
        {
            const p2p::peer_challenge chall = p2pmsg::get_peer_challenge_from_msg(*content->message_as_Peer_Challenge_Message());

            // Check whether contract ids match.
            if (chall.contract_id != conf::cfg.contractid)
                return -1;
            
            // Sending the challenge response to the sender.
            flatbuffers::FlatBufferBuilder fbuf(1024);
            p2pmsg::create_peer_challenge_response_from_challenge(fbuf, chall.challenge);
            std::string_view msg = std::string_view(
                reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
            return session.send(msg);
        }
        else if (content_message_type == p2pmsg::Message_Peer_Challenge_Response_Message) // message is a peer challenge response
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
            LOG_DEBUG << "Cannot accept messages. Peer challenge unresolved. " << session.display_name();
            return 0;
        }

        if (content_message_type == p2pmsg::Message_Peer_List_Response_Message) // This message is the peer list response message.
        {
            p2p::merge_peer_list(p2pmsg::create_peer_list_response_from_msg(*content->message_as_Peer_List_Response_Message()));
        }
        else if (content_message_type == p2pmsg::Message_Peer_List_Request_Message) // This message is the peer list request message.
        {
            p2p::send_known_peer_list(&session);
        }
        else if (content_message_type == p2pmsg::Message_Available_Capacity_Announcement_Message) // This message is the available capacity announcement message.
        {
            if (session.known_ipport.has_value())
            {
                const p2pmsg::Available_Capacity_Announcement_Message *announcement_msg = content->message_as_Available_Capacity_Announcement_Message();
                p2p::update_known_peer_available_capacity(session.known_ipport.value(), announcement_msg->available_capacity(), announcement_msg->timestamp());
            }
        }
        else if (content_message_type == p2pmsg::Message_Peer_Requirement_Announcement_Message) // This message is a peer requirement announcement message.
        {
            const p2pmsg::Peer_Requirement_Announcement_Message *announcement_msg = content->message_as_Peer_Requirement_Announcement_Message();
            session.need_consensus_msg_forwarding = announcement_msg->need_consensus_msg_forwarding();
            if (session.need_consensus_msg_forwarding)
            {
                LOG_DEBUG << "Consensus message forwaring is required for " << session.display_name();
            }
            else
            {
                LOG_DEBUG << "Consensus message forwaring is not required for " << session.display_name();
            }
        }
        else if (content_message_type == p2pmsg::Message_Proposal_Message) // message is a proposal message
        {
            // We only trust proposals coming from trusted peers.
            if (p2pmsg::validate_container_trust(container) != 0)
            {
                session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "Proposal rejected due to trust failure. " << session.display_name();
                return 0;
            }

            if (handle_proposal_message(container, content) != 0)
                LOG_DEBUG << "Proposal rejected. Maximum proposal count reached. " << session.display_name();
        }
        else if (content_message_type == p2pmsg::Message_NonUnl_Proposal_Message) //message is a non-unl proposal message
        {
            if (handle_nonunl_proposal_message(container, content) != 0)
                LOG_DEBUG << "Nonunl proposal rejected. Maximum nonunl proposal count reached. " << session.display_name();
        }
        else if (content_message_type == p2pmsg::Message_Npl_Message) //message is a NPL message
        {
            if (p2pmsg::validate_container_trust(container) != 0)
            {
                session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "NPL message rejected due to trust failure. " << session.display_name();
                return 0;
            }

            handle_npl_message(container, content);
        }
        else if (content_message_type == p2pmsg::Message_State_Request_Message)
        {
            // Check the cap and insert request with lock.
            std::scoped_lock<std::mutex> lock(ctx.collected_msgs.state_requests_mutex);

            // If max number of state requests reached skip the rest.
            if (ctx.collected_msgs.state_requests.size() < p2p::STATE_REQ_LIST_CAP)
            {
                std::string state_request_msg(reinterpret_cast<const char *>(content_ptr), content_size);
                ctx.collected_msgs.state_requests.push_back(std::make_pair(session.pubkey, std::move(state_request_msg)));
            }
            else
            {
                LOG_DEBUG << "State request rejected. Maximum state request count reached. " << session.display_name();
            }
        }
        else if (content_message_type == p2pmsg::Message_State_Response_Message)
        {
            if (state_sync::ctx.is_syncing) // Only accept state responses if state is syncing.
            {
                // Check the cap and insert state_response with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.state_responses_mutex);

                // If max number of state responses reached skip the rest.
                if (ctx.collected_msgs.state_responses.size() < p2p::STATE_RES_LIST_CAP)
                {
                    std::string response(reinterpret_cast<const char *>(content_ptr), content_size);
                    ctx.collected_msgs.state_responses.push_back(std::make_pair(session.pubkey, std::move(response)));
                }
                else
                {
                    LOG_DEBUG << "State response rejected. Maximum state response count reached. " << session.display_name();
                }
            }
        }
        else if (content_message_type == p2pmsg::Message_History_Request_Message) //message is a lcl history request message
        {
            // Check the cap and insert request with lock.
            std::scoped_lock<std::mutex> lock(ledger::sync_ctx.list_mutex);

            // If max number of history requests reached skip the rest.
            if (ledger::sync_ctx.collected_history_requests.size() < ledger::HISTORY_REQ_LIST_CAP)
            {
                const p2p::history_request hr = p2pmsg::create_history_request_from_msg(*content->message_as_History_Request_Message(), container->lcl());
                ledger::sync_ctx.collected_history_requests.push_back(std::make_pair(session.pubkey, std::move(hr)));
            }
            else
            {
                LOG_DEBUG << "History request rejected. Maximum history request count reached. " << session.display_name();
            }
        }
        else if (content_message_type == p2pmsg::Message_History_Response_Message) //message is a lcl history response message
        {
            if (ledger::sync_ctx.is_syncing) // Only accept history responses if ledger is syncing.
            {
                // Check the cap and insert response with lock.
                std::scoped_lock<std::mutex> lock(ledger::sync_ctx.list_mutex);

                // If max number of history respoinses reached skip the rest.
                if (ledger::sync_ctx.collected_history_responses.size() < ledger::HISTORY_RES_LIST_CAP)
                {
                    const p2p::history_response hr = p2pmsg::create_history_response_from_msg(*content->message_as_History_Response_Message());
                    ledger::sync_ctx.collected_history_responses.push_back(std::move(hr));
                }
                else
                {
                    LOG_DEBUG << "History response rejected. Maximum history response count reached. " << session.display_name();
                }
            }
        }
        else
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Received invalid peer message type. " << session.display_name();
        }
        return 0;
    }

    /**
     * Handles messages that we receive from ourselves.
     */
    int handle_self_message(std::string_view message)
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

        const p2pmsg::Message content_message_type = content->message_type(); //i.e - proposal, npl, state request, state response, etc

        if (content_message_type == p2pmsg::Message_Proposal_Message) // message is a proposal message
        {
            if (handle_proposal_message(container, content) != 0)
                LOG_DEBUG << "Proposal rejected. Maximum proposal count reached. self";
        }
        else if (content_message_type == p2pmsg::Message_NonUnl_Proposal_Message) //message is a non-unl proposal message
        {
            if (handle_nonunl_proposal_message(container, content) != 0)
                LOG_DEBUG << "Nonunl proposal rejected. Maximum nonunl proposal count reached. self";
        }
        else if (content_message_type == p2pmsg::Message_Npl_Message) //message is a NPL message
            handle_npl_message(container, content);

        return 0;
    }

    /**
     * Handle proposal message.
     * @param container Message container.
     * @param content Message content.
     * @return returns 0 if proposal is pushed to the list, otherwise -1.
    */
    int handle_proposal_message(const p2pmsg::Container *container, const p2pmsg::Content *content)
    {
        // Check the cap and insert proposal with lock.
        std::scoped_lock<std::mutex> lock(ctx.collected_msgs.proposals_mutex);

        // If max number of proposals reached skip the rest.
        if (ctx.collected_msgs.proposals.size() == p2p::PROPOSAL_LIST_CAP)
            return -1;

        ctx.collected_msgs.proposals.push_back(
            p2pmsg::create_proposal_from_msg(*content->message_as_Proposal_Message(), container->pubkey(), container->timestamp(), container->lcl()));

        return 0;
    }

    /**
     * Handle nonunl proposal message.
     * @param container Message container.
     * @param content Message content.
     * @return returns 0 if nonunl proposal is pushed to the list, otherwise -1.
    */
    int handle_nonunl_proposal_message(const p2pmsg::Container *container, const p2pmsg::Content *content)
    {
        // Check the cap and insert proposal with lock.
        std::scoped_lock<std::mutex> lock(ctx.collected_msgs.nonunl_proposals_mutex);

        // If max number of nonunl proposals reached skip the rest.
        if (ctx.collected_msgs.nonunl_proposals.size() == p2p::NONUNL_PROPOSAL_LIST_CAP)
            return -1;

        ctx.collected_msgs.nonunl_proposals.push_back(
            p2pmsg::create_nonunl_proposal_from_msg(*content->message_as_NonUnl_Proposal_Message(), container->timestamp()));

        return 0;
    }

    void handle_npl_message(const p2pmsg::Container *container, const p2pmsg::Content *content)
    {
        const p2pmsg::Npl_Message *npl_p2p_msg = content->message_as_Npl_Message();
        npl_message msg;
        msg.data = msg::fbuf::flatbuff_bytes_to_sv(npl_p2p_msg->data());
        msg.pubkey = msg::fbuf::flatbuff_bytes_to_sv(container->pubkey());
        msg.lcl = msg::fbuf::flatbuff_bytes_to_sv(container->lcl());

        if (!consensus::push_npl_message(msg))
        {
            LOG_DEBUG << "NPL message from self enqueue failure.";
        }
    }

    //peer session on message callback method
    int handle_peer_close(const p2p::peer_comm_session &session)
    {
        {
            // Erase the corresponding pubkey peer connection if it's this session.
            std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);
            const auto itr = ctx.peer_connections.find(session.pubkey);
            if (itr != ctx.peer_connections.end() && itr->second == &session)
            {
                ctx.peer_connections.erase(itr);
            }
        }

        // Update peer properties to default on peer close.
        if (session.known_ipport.has_value())
            p2p::update_known_peer_available_capacity(session.known_ipport.value(), -1, 0);

        return 0;
    }

    /**
     * Logic related to peer sessions on verfied is invoked here.
     */
    void handle_peer_on_verified(p2p::peer_comm_session &session)
    {
        // Sending newly verified node the requirement of consensus msg fowarding if this node is weakly connected.
        if (p2p::is_weakly_connected)
        {
            p2p::send_peer_requirement_announcement(is_weakly_connected, &session);
        }
    }
} // namespace p2p