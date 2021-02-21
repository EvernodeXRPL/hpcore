#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../consensus.hpp"
#include "../crypto.hpp"
#include "../util/util.hpp"
#include "../util/rollover_hashset.hpp"
#include "../hplog.hpp"
#include "../msg/fbuf2/p2pmsg_generated.h"
#include "../msg/fbuf2/p2pmsg_conversion.hpp"
#include "../msg/fbuf2/common_helpers.hpp"
#include "../ledger/ledger.hpp"
#include "peer_comm_session.hpp"
#include "p2p.hpp"
#include "../unl.hpp"

namespace p2pmsg2 = msg::fbuf2::p2pmsg;

namespace p2p
{
    // The set of recent peer message hashes used for duplicate detection.
    util::rollover_hashset recent_peermsg_hashes(200);

    /**
     * This gets hit every time a peer connects to HP via the peer port (configured in config).
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
        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg2::create_msg_from_peer_challenge(fbuf, session.issued_challenge);
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

        const decoded_peer_message decoded = p2pmsg2::decode_p2p_message(message);

        if (decoded.msg_type == p2pmsg2::P2PMsgContent_NONE)
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Received invalid peer message type. " << session.display_name();
            return 0;
        }
        else if (!recent_peermsg_hashes.try_emplace(crypto::get_hash(message)))
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_DUPMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Duplicate peer message. " << session.display_name();
            return 0;
        }
        // Check whether the message is qualified for message forwarding.
        else if (p2p::validate_for_peer_msg_forwarding(session, decoded.msg_type, decoded.originated_on))
        {
            // Npl messages and consensus proposals are forwarded only to unl nodes if relavent flags (npl and consensus) are set to private.
            // If consensus and npl flags are public, these messages are forward to all the connected nodes.
            const bool unl_only = (!conf::cfg.contract.is_npl_public && decoded.msg_type == p2pmsg2::P2PMsgContent_NplMsg) ||
                                  (!conf::cfg.contract.is_consensus_public && decoded.msg_type == p2pmsg2::P2PMsgContent_ProposalMsg);
            if (session.need_consensus_msg_forwarding)
            {
                // Forward messages received by weakly connected nodes to other peers.
                p2p::broadcast_message(message, false, false, unl_only, &session);
            }
            else
            {
                // Forward message received from other nodes to weakly connected peers.
                p2p::broadcast_message(message, false, true, unl_only, &session);
            }
        }

        if (decoded.msg_type == p2pmsg2::P2PMsgContent_PeerChallengeMsg)
        {
            const p2p::peer_challenge &chall = std::get<const p2p::peer_challenge>(decoded.message);

            // Check whether contract ids match.
            if (chall.contract_id != conf::cfg.contract.id)
            {
                LOG_ERROR << "Contract id mismatch. Dropping connection " << session.display_name();
                return -1;
            }

            // Remember the roundtime reported by this peer.
            session.reported_roundtime = chall.roundtime;

            // Sending the challenge response to the sender.
            flatbuffers::FlatBufferBuilder fbuf;
            p2pmsg2::create_peer_challenge_response_from_challenge(fbuf, chall.challenge);
            return session.send(msg::fbuf2::builder_to_string_view(fbuf));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_PeerChallengeResponseMsg)
        {
            // Ignore if challenge is already resolved.
            if (session.challenge_status == comm::CHALLENGE_ISSUED)
                return p2p::resolve_peer_challenge(session, std::get<const p2p::peer_challenge_response>(decoded.message));
        }

        if (session.challenge_status != comm::CHALLENGE_VERIFIED)
        {
            LOG_DEBUG << "Cannot accept messages. Peer challenge unresolved. " << session.display_name();
            return 0;
        }

        if (decoded.msg_type == p2pmsg2::P2PMsgContent_PeerListResponseMsg)
        {
            p2p::merge_peer_list(std::get<const std::vector<conf::peer_properties>>(decoded.message));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_PeerListRequestMsg)
        {
            p2p::send_known_peer_list(&session);
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_PeerCapacityAnnouncementMsg)
        {
            if (session.known_ipport.has_value())
            {
                const p2p::peer_capacity_announcement &ann = std::get<const p2p::peer_capacity_announcement>(decoded.message);
                p2p::update_known_peer_available_capacity(session.known_ipport.value(), ann.available_capacity, ann.timestamp);
            }
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_PeerRequirementAnnouncementMsg)
        {
            const p2p::peer_requirement_announcement &ann = std::get<const p2p::peer_requirement_announcement>(decoded.message);
            session.need_consensus_msg_forwarding = ann.need_consensus_msg_forwarding;
            LOG_DEBUG << "Peer requirement: " << session.display_name() << " consensus msg forwarding:" << ann.need_consensus_msg_forwarding;
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_ProposalMsg)
        {
            handle_proposal_message(std::get<const p2p::proposal>(decoded.message));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_NonUnlProposalMsg)
        {
            handle_nonunl_proposal_message(std::get<const p2p::nonunl_proposal>(decoded.message));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_NplMsg)
        {
            handle_npl_message(std::get<const p2p::npl_message>(decoded.message));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_HpfsRequestMsg)
        {
            const p2p::hpfs_request hr = std::get<const p2p::hpfs_request>(decoded.message);
            if (hr.mount_id == sc::contract_fs.mount_id)
            {
                // Check the cap and insert request with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.contract_hpfs_requests_mutex);

                // If max number of state requests reached skip the rest.
                if (ctx.collected_msgs.contract_hpfs_requests.size() < p2p::HPFS_REQ_LIST_CAP)
                    ctx.collected_msgs.contract_hpfs_requests.push_back(std::make_pair(session.pubkey, std::move(hr)));
                else
                    LOG_DEBUG << "Hpfs contract fs request rejected. Maximum hpfs contract fs request count reached. " << session.display_name();
            }
            else if (hr.mount_id == ledger::ledger_fs.mount_id)
            {
                // Check the cap and insert request with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.ledger_hpfs_requests_mutex);

                // If max number of state requests reached skip the rest.
                if (ctx.collected_msgs.ledger_hpfs_requests.size() < p2p::HPFS_REQ_LIST_CAP)
                    ctx.collected_msgs.ledger_hpfs_requests.push_back(std::make_pair(session.pubkey, std::move(hr)));
                else
                    LOG_DEBUG << "Hpfs ledger fs request rejected. Maximum hpfs ledger fs request count reached. " << session.display_name();
            }
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_HpfsResponseMsg)
        {
            // TODO
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
        const decoded_peer_message decoded = p2pmsg2::decode_p2p_message(message);

        if (decoded.msg_type == p2pmsg2::P2PMsgContent_ProposalMsg)
        {
            handle_proposal_message(std::get<const p2p::proposal>(decoded.message));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_NonUnlProposalMsg)
        {
            handle_nonunl_proposal_message(std::get<const p2p::nonunl_proposal>(decoded.message));
        }
        else if (decoded.msg_type == p2pmsg2::P2PMsgContent_NplMsg)
        {
            handle_npl_message(std::get<const p2p::npl_message>(decoded.message));
        }

        return 0;
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