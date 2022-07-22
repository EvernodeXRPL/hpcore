#include "../pchheader.hpp"
#include "../util/rollover_hashset.hpp"
#include "../msg/fbuf/p2pmsg_generated.h"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../crypto.hpp"
#include "../sc/hpfs_log_sync.hpp"
#include "../sc/sc.hpp"
#include "../ledger/ledger.hpp"
#include "peer_comm_session.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace p2p
{
    // Max size of messages which are subjected to duplicate message check.
    constexpr size_t MAX_SIZE_FOR_DUP_CHECK = 1 * 1024 * 1024; // 1 MB

    // The set of recent peer message hashes used for duplicate detection.
    util::rollover_hashset recent_peermsg_hashes(200);

    /**
     * This gets hit every time a peer connects to HP via the peer port (configured in config).
     * @param session connected session.
     * @return returns 0 if connection is successful and peer challenge is sent otherwise, -1.
     */
    int peer_comm_session::handle_connect()
    {
        // Skip new inbound connection if max inbound connection cap is reached.
        if (is_inbound && calculate_available_capacity() == 0)
        {
            LOG_DEBUG << "Max peer connection cap reached. Rejecting new peer connection [" << display_name() << "]";
            return -1;
        }

        // Send peer challenge.
        flatbuffers::FlatBufferBuilder fbuf;
        p2pmsg::create_msg_from_peer_challenge(fbuf, issued_challenge);
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(fbuf.GetBufferPointer()), fbuf.GetSize());
        send(msg);
        challenge_status = comm::CHALLENGE_STATUS::CHALLENGE_ISSUED;
        return 0;
    }

    /**
     * Returns the priority that should be assigned to the message.
     * @return 0 if bad message. 1 or 2 if correct priority was assigned.
     */
    int peer_comm_session::get_message_priority(std::string_view msg)
    {
        if (!p2pmsg::verify_peer_message(msg))
        {
            LOG_DEBUG << "Flatbuffer verify: Bad peer message.";
            return 0;
        }

        const auto p2p_msg = p2pmsg::GetP2PMsg(msg.data());
        const msg::fbuf::p2pmsg::P2PMsgContent type = p2p_msg->content_type();

        if (type == p2pmsg::P2PMsgContent_ProposalMsg || type == p2pmsg::P2PMsgContent_NonUnlProposalMsg)
            return 1; // High priority
        else
            return 2; // Low priority
    }

    /**
     * Peer session on message callback method. Validate and handle each type of peer messages.
     * @return 0 on normal execution. -1 when session needs to be closed as a result of message handling.
     */
    int peer_comm_session::handle_message(std::string_view msg)
    {
        const size_t message_size = msg.size();
        // Adding message size to peer message characters(bytes) per minute counter.
        increment_metric(comm::SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, message_size);

        const peer_message_info mi = p2pmsg::get_peer_message_info(msg, this);
        if (!mi.p2p_msg) // Message buffer will be null if peer message was too old.
            return 0;

        // Messages larger than the duplicate message threshold is ignored from the duplicate message check
        // due to the overhead in hash generation for larger messages.
        if (message_size <= MAX_SIZE_FOR_DUP_CHECK && !recent_peermsg_hashes.try_emplace(crypto::get_hash(msg)))
        {
            increment_metric(comm::SESSION_THRESHOLDS::MAX_DUPMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Duplicate peer message. type:" << mi.type << " from:" << display_name();
            return 0;
        }

        // Check whether the message is qualified for message forwarding.
        if (p2p::validate_for_peer_msg_forwarding(*this, mi.type, mi.originated_on))
        {
            // Npl messages and consensus proposals are forwarded only to unl nodes if relavent flags (npl and consensus) are set to private.
            // If consensus and npl flags are public, these messages are forward to all the connected nodes.
            const bool unl_only = (conf::cfg.contract.npl.mode != conf::MODE::PUBLIC && mi.type == p2pmsg::P2PMsgContent_NplMsg) ||
                                  (conf::cfg.contract.consensus.mode != conf::MODE::PUBLIC && mi.type == p2pmsg::P2PMsgContent_ProposalMsg);
            if (need_consensus_msg_forwarding)
            {
                // Forward messages received by weakly connected nodes to other peers.
                p2p::broadcast_message(msg, false, false, unl_only, this);
            }
            else
            {
                // Forward message received from other nodes to weakly connected peers.
                p2p::broadcast_message(msg, false, true, unl_only, this);
            }
        }

        if (mi.type == p2pmsg::P2PMsgContent_PeerChallengeMsg)
        {
            const p2p::peer_challenge chall = p2pmsg::create_peer_challenge_from_msg(mi);

            // Check whether contract ids match.
            if (chall.contract_id != conf::cfg.contract.id)
            {
                LOG_ERROR << "Contract id mismatch. Dropping connection " << display_name();
                return -1;
            }

            // Remember the time config reported by this peer.
            reported_time_config = chall.time_config;

            // Whether this node is a full history node or not.
            is_full_history = chall.is_full_history;

            // Sending the challenge response to the sender.
            flatbuffers::FlatBufferBuilder fbuf;
            p2pmsg::create_peer_challenge_response_from_challenge(fbuf, chall.challenge);
            return send(msg::fbuf::builder_to_string_view(fbuf));
        }
        else if (mi.type == p2pmsg::P2PMsgContent_PeerChallengeResponseMsg)
        {
            // Ignore if challenge is already resolved.
            if (challenge_status == comm::CHALLENGE_STATUS::CHALLENGE_ISSUED)
                return p2p::resolve_peer_challenge(*this, p2pmsg::create_peer_challenge_response_from_msg(mi));
        }

        if (challenge_status != comm::CHALLENGE_STATUS::CHALLENGE_VERIFIED)
        {
            LOG_DEBUG << "Cannot accept messages. Peer challenge unresolved. " << display_name();
            return 0;
        }

        if (mi.type == p2pmsg::P2PMsgContent_PeerListResponseMsg)
        {
            const std::vector<p2p::peer_properties> merge_peers = p2pmsg::create_peer_list_response_from_msg(mi);
            p2p::merge_peer_list("Peer_Discovery", &merge_peers, NULL, this);
        }
        else if (mi.type == p2pmsg::P2PMsgContent_PeerListRequestMsg)
        {
            p2p::send_known_peer_list(this);
        }
        else if (mi.type == p2pmsg::P2PMsgContent_PeerCapacityAnnouncementMsg)
        {
            if (known_ipport.has_value())
            {
                const p2p::peer_capacity_announcement ann = p2pmsg::create_peer_capacity_announcement_from_msg(mi);
                p2p::update_known_peer_available_capacity(known_ipport.value(), ann.available_capacity, ann.timestamp);
            }
        }
        else if (mi.type == p2pmsg::P2PMsgContent_PeerRequirementAnnouncementMsg)
        {
            const p2p::peer_requirement_announcement ann = p2pmsg::create_peer_requirement_announcement_from_msg(mi);
            need_consensus_msg_forwarding = ann.need_consensus_msg_forwarding;
            LOG_DEBUG << "Peer requirement: " << display_name() << " consensus msg forwarding:" << ann.need_consensus_msg_forwarding;
        }
        else if (mi.type == p2pmsg::P2PMsgContent_NonUnlProposalMsg)
        {
            handle_nonunl_proposal_message(p2pmsg::create_nonunl_proposal_from_msg(mi));
        }
        else if (mi.type == p2pmsg::P2PMsgContent_ProposalMsg)
        {
            const util::h32 hash = p2pmsg::verify_proposal_msg_trust(mi);
            if (hash == util::h32_empty)
            {
                increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "Proposal rejected due to trust failure. " << display_name();
                return 0;
            }

            handle_proposal_message(p2pmsg::create_proposal_from_msg(mi, hash));
        }
        else if (mi.type == p2pmsg::P2PMsgContent_NplMsg)
        {
            if (!p2pmsg::verify_npl_msg_trust(mi))
            {
                increment_metric(comm::SESSION_THRESHOLDS::MAX_BADSIGMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "Npl message rejected due to trust failure. " << display_name();
                return 0;
            }

            handle_npl_message(p2pmsg::create_npl_from_msg(mi));
        }
        else if (mi.type == p2pmsg::P2PMsgContent_HpfsRequestMsg)
        {
            const p2p::hpfs_request hr = p2pmsg::create_hpfs_request_from_msg(mi);
            if (hr.mount_id == sc::contract_fs.mount_id)
            {
                // Check the cap and insert request with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.contract_hpfs_requests_mutex);

                // If max number of state requests reached skip the rest.
                if (ctx.collected_msgs.contract_hpfs_requests.size() < p2p::HPFS_REQ_LIST_CAP)
                    ctx.collected_msgs.contract_hpfs_requests.push_back(std::make_pair(pubkey, std::move(hr)));
                else
                    LOG_DEBUG << "Hpfs contract fs request rejected. Maximum hpfs contract fs request count reached. " << display_name();
            }
            else if (hr.mount_id == ledger::ledger_fs.mount_id)
            {
                // Check the cap and insert request with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.ledger_hpfs_requests_mutex);

                // If max number of state requests reached skip the rest.
                if (ctx.collected_msgs.ledger_hpfs_requests.size() < p2p::HPFS_REQ_LIST_CAP)
                    ctx.collected_msgs.ledger_hpfs_requests.push_back(std::make_pair(pubkey, std::move(hr)));
                else
                    LOG_DEBUG << "Hpfs ledger fs request rejected. Maximum hpfs ledger fs request count reached. " << display_name();
            }
        }
        else if (mi.type == p2pmsg::P2PMsgContent_HpfsResponseMsg)
        {
            const p2pmsg::HpfsResponseMsg &resp_msg = *mi.p2p_msg->content_as_HpfsResponseMsg();

            // Only accept hpfs responses if hpfs fs is syncing.
            if (sc::contract_sync_worker.is_syncing && resp_msg.mount_id() == sc::contract_fs.mount_id)
            {
                // Check the cap and insert state_response with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.contract_hpfs_responses_mutex);

                // If max number of state responses reached skip the rest.
                if (ctx.collected_msgs.contract_hpfs_responses.size() < p2p::HPFS_RES_LIST_CAP)
                    ctx.collected_msgs.contract_hpfs_responses.push_back(std::make_pair(uniqueid, std::string(msg)));
                else
                    LOG_DEBUG << "Contract hpfs response rejected. Maximum response count reached. " << display_name();
            }
            else if (ledger::ledger_sync_worker.is_syncing && resp_msg.mount_id() == ledger::ledger_fs.mount_id)
            {
                // Check the cap and insert state_response with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.ledger_hpfs_responses_mutex);

                // If max number of state responses reached skip the rest.
                if (ctx.collected_msgs.ledger_hpfs_responses.size() < p2p::HPFS_RES_LIST_CAP)
                    ctx.collected_msgs.ledger_hpfs_responses.push_back(std::make_pair(uniqueid, std::string(msg)));
                else
                    LOG_DEBUG << "Ledger hpfs response rejected. Maximum response count reached. " << display_name();
            }
        }
        else if (mi.type == p2pmsg::P2PMsgContent_HpfsLogRequest)
        {
            if (conf::cfg.node.history == conf::HISTORY::FULL)
            {
                // Check the cap and insert log record request with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.hpfs_log_request_mutex);

                // If max number of log record requests reached, skip the rest.
                if (ctx.collected_msgs.hpfs_log_requests.size() < p2p::LOG_RECORD_REQ_LIST_CAP)
                {
                    const p2p::hpfs_log_request hpfs_log_request = p2pmsg::create_hpfs_log_request_from_msg(mi);
                    ctx.collected_msgs.hpfs_log_requests.push_back(std::make_pair(uniqueid, std::move(hpfs_log_request)));
                }
                else
                    LOG_DEBUG << "Hpfs log request rejected. Maximum request count reached. " << display_name();
            }
        }
        else if (mi.type == p2pmsg::P2PMsgContent_HpfsLogResponse)
        {
            if (conf::cfg.node.history == conf::HISTORY::FULL && sc::hpfs_log_sync::sync_ctx.is_syncing)
            {
                // Check the cap and insert log record response with lock.
                std::scoped_lock<std::mutex> lock(ctx.collected_msgs.hpfs_log_response_mutex);

                // If max number of log record responses reached, skip the rest.
                if (ctx.collected_msgs.hpfs_log_responses.size() < p2p::LOG_RECORD_RES_LIST_CAP)
                {
                    const p2p::hpfs_log_response hpfs_log_response = p2pmsg::create_hpfs_log_response_from_msg(mi);
                    ctx.collected_msgs.hpfs_log_responses.push_back(std::make_pair(uniqueid, std::move(hpfs_log_response)));
                }
                else
                    LOG_DEBUG << "Hpfs log response rejected. Maximum response count reached. " << display_name();
            }
        }
        else
        {
            increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
            LOG_DEBUG << "Received invalid peer message type [" << mi.type << "]. " << display_name();
        }
        return 0;
    }

    void peer_comm_session::handle_close()
    {
        {
            // Erase the corresponding pubkey peer connection if it's this session.
            std::scoped_lock<std::mutex> lock(ctx.peer_connections_mutex);
            const auto itr = ctx.peer_connections.find(pubkey);
            if (itr != ctx.peer_connections.end() && itr->second == this)
            {
                ctx.peer_connections.erase(itr);
            }
        }

        // Update peer properties to default on peer close.
        if (known_ipport.has_value())
            p2p::update_known_peer_available_capacity(known_ipport.value(), -1, 0);
    }

    /**
     * Logic related to peer sessions on verfied is invoked here.
     */
    void peer_comm_session::handle_on_verified()
    {
        // Sending newly verified node the requirement of consensus msg fowarding if this node is weakly connected.
        if (status::get_weakly_connected())
            p2p::send_peer_requirement_announcement(true, this);
    }

} // namespace p2p