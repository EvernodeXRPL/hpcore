#include "common_helpers.hpp"
#include "p2pmsg_conversion.hpp"
#include "../../hpfs/hpfs_mount.hpp"

namespace msg::fbuf2::p2pmsg
{
    // Length of a peer connection challange.
    constexpr size_t PEERCHALLENGE_LEN = 16;

    // Max size of messages which are subjected to time (too old) check.
    constexpr size_t MAX_SIZE_FOR_TIME_CHECK = 1 * 1024 * 1024; // 1 MB

    /**
     * This section contains Flatbuffer message reading/writing helpers.
     * These helpers are mainly used by peer_session_handler and other components which sends outgoing p2p messages.
     * 
     * A p2p flatbuffer message is a bucket with hp version and the message 'content'.
     */

    //---Flatbuf to std---//

    const std::variant<
        const p2p::peer_challenge,
        const p2p::peer_challenge_response,
        const p2p::nonunl_proposal,
        const std::vector<conf::peer_properties>,
        const p2p::peer_capacity_announcement,
        const p2p::peer_requirement_announcement,
        int>
    decode_p2p_message(std::string_view message)
    {
        //Accessing message buffer
        const uint8_t *buf = reinterpret_cast<const uint8_t *>(message.data());
        const size_t buf_size = message.size();

        //Verify container message using flatbuffer verifier
        flatbuffers::Verifier verifier(buf, buf_size, 16, 100);
        if (!VerifyP2PMsgBuffer(verifier))
        {
            LOG_DEBUG << "Flatbuffer verify: Bad peer message.";
            return -1;
        }

        const P2PMsg *pm = GetP2PMsg(buf);

        //check message timestamp (ignore this for large messages).
        if (buf_size <= MAX_SIZE_FOR_TIME_CHECK)
        {
            const uint64_t time_now = util::get_epoch_milliseconds();
            if (pm->created_on() < (time_now - (conf::cfg.contract.roundtime * 4)))
            {
                LOG_DEBUG << "Peer message is too old.";
                return -1;
            }
        }

        switch (pm->content_type())
        {
        case P2PMsgContent_PeerChallengeMsg:
            return create_peer_challenge_from_msg(*pm->content_as_PeerChallengeMsg());
        case P2PMsgContent_PeerChallengeResponseMsg:
            return create_peer_challenge_response_from_msg(*pm->content_as_PeerChallengeResponseMsg());
        case P2PMsgContent_NonUnlProposalMsg:
            return create_nonunl_proposal_from_msg(*pm->content_as_NonUnlProposalMsg());
        case P2PMsgContent_PeerListResponseMsg:
            return create_peer_list_response_from_msg(*pm->content_as_PeerListResponseMsg());
        case P2PMsgContent_PeerCapacityAnnouncementMsg:
            return create_peer_capacity_announcement_from_msg(*pm->content_as_PeerCapacityAnnouncementMsg());
        case P2PMsgContent_PeerRequirementAnnouncementMsg:
            return create_peer_requirement_announcement_from_msg(*pm->content_as_PeerRequirementAnnouncementMsg());
        default:
            LOG_DEBUG << "Unrecognized peer message type.";
            return -1;
        }
    }

    const p2p::peer_challenge create_peer_challenge_from_msg(const PeerChallengeMsg &msg)
    {
        return {
            std::string(flatbuf_str_to_sv(msg.contract_id())),
            msg.roundtime(),
            std::string(flatbuf_str_to_sv(msg.challenge()))};
    }

    const p2p::peer_challenge_response create_peer_challenge_response_from_msg(const PeerChallengeResponseMsg &msg)
    {
        return {
            std::string(flatbuf_str_to_sv(msg.challenge())),
            std::string(flatbuf_bytes_to_sv(msg.sig())),
            std::string(flatbuf_bytes_to_sv(msg.pubkey()))};
    }

    const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnlProposalMsg &msg)
    {
        p2p::nonunl_proposal nup;

        if (msg.user_inputs())
            nup.user_inputs = flatbuf_user_input_group_to_user_input_map(msg.user_inputs());

        return nup;
    }

    const std::vector<conf::peer_properties> create_peer_list_response_from_msg(const PeerListResponseMsg &msg)
    {
        return flatbuf_peer_propertieslist_to_peer_propertiesvector(msg.peer_list());
    }

    const p2p::peer_capacity_announcement create_peer_capacity_announcement_from_msg(const PeerCapacityAnnouncementMsg &msg)
    {
        return {
            msg.available_capacity(),
            msg.timestamp()};
    }

    const p2p::peer_requirement_announcement create_peer_requirement_announcement_from_msg(const PeerRequirementAnnouncementMsg &msg)
    {
        return {
            msg.need_consensus_msg_forwarding()};
    }

    const p2p::hpfs_request create_hpfs_request_from_msg(const HpfsRequestMsg &msg)
    {
        p2p::hpfs_request hr;
        hr.mount_id = msg.mount_id();
        hr.block_id = msg.block_id();
        hr.is_file = msg.is_file();
        hr.parent_path = flatbuf_str_to_sv(msg.parent_path());
        hr.expected_hash = flatbuf_bytes_to_hash(msg.expected_hash());
        return hr;
    }

    const std::set<std::string> flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec)
    {
        std::set<std::string> set;
        for (auto el : *fbvec)
            set.emplace(std::string(flatbuf_bytes_to_sv(el->array())));
        return set;
    }

    const std::unordered_map<std::string, std::list<usr::submitted_user_input>>
    flatbuf_user_input_group_to_user_input_map(const flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>> *fbvec)
    {
        std::unordered_map<std::string, std::list<usr::submitted_user_input>> map;
        map.reserve(fbvec->size());
        for (const UserInputGroup *group : *fbvec)
        {
            std::list<usr::submitted_user_input> user_inputs_list;

            for (const auto msg : *group->messages())
            {
                user_inputs_list.push_back(usr::submitted_user_input{
                    std::string(flatbuf_bytes_to_sv(msg->input_container())),
                    std::string(flatbuf_bytes_to_sv(msg->sig())),
                    static_cast<util::PROTOCOL>(msg->protocol())});
            }

            map.emplace(flatbuf_bytes_to_sv(group->pubkey()), std::move(user_inputs_list));
        }
        return map;
    }

    void flatbuf_hpfsfshashentry_to_hpfsfshashentry(std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entries, const flatbuffers::Vector<flatbuffers::Offset<HpfsFSHashEntry>> *fhashes)
    {
        for (const HpfsFSHashEntry *f_hash : *fhashes)
        {
            p2p::hpfs_fs_hash_entry entry;
            entry.name = flatbuf_str_to_sv(f_hash->name());
            entry.is_file = f_hash->is_file();
            entry.hash = flatbuf_bytes_to_hash(f_hash->hash());

            fs_entries.emplace(entry.name, std::move(entry));
        }
    }

    const std::vector<conf::peer_properties>
    flatbuf_peer_propertieslist_to_peer_propertiesvector(const flatbuffers::Vector<flatbuffers::Offset<PeerProperties>> *fbvec)
    {
        std::vector<conf::peer_properties> peers;

        for (const PeerProperties *peer : *fbvec)
        {
            conf::peer_properties properties;

            properties.ip_port.host_address = flatbuf_str_to_sv(peer->host_address());
            properties.ip_port.port = peer->port();
            properties.timestamp = peer->timestamp();
            properties.available_capacity = peer->available_capacity();

            peers.push_back(properties);
        }
        return peers;
    }

    //---std to Flatbuf---//

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>>>
    user_input_map_to_flatbuf_user_input_group(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, std::list<usr::submitted_user_input>> &map)
    {
        std::vector<flatbuffers::Offset<UserInputGroup>> fbvec;
        fbvec.reserve(map.size());
        for (const auto &[pubkey, msglist] : map)
        {
            std::vector<flatbuffers::Offset<UserInput>> fbmsgsvec;
            for (const usr::submitted_user_input &msg : msglist)
            {
                fbmsgsvec.push_back(CreateUserInput(
                    builder,
                    sv_to_flatbuf_bytes(builder, msg.input_container),
                    sv_to_flatbuf_bytes(builder, msg.sig),
                    static_cast<uint8_t>(msg.protocol)));
            }

            fbvec.push_back(CreateUserInputGroup(
                builder,
                sv_to_flatbuf_bytes(builder, pubkey),
                builder.CreateVector(fbmsgsvec)));
        }
        return builder.CreateVector(fbvec);
    }

    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<HpfsFSHashEntry>>>
    hpfsfshashentry_to_flatbuf_hpfsfshashentry(
        flatbuffers::FlatBufferBuilder &builder,
        std::vector<hpfs::child_hash_node> &hash_nodes)
    {
        std::vector<flatbuffers::Offset<HpfsFSHashEntry>> fbvec;
        fbvec.reserve(hash_nodes.size());
        for (auto const &hash_node : hash_nodes)
        {
            flatbuffers::Offset<HpfsFSHashEntry> hpfs_fs_entry = CreateHpfsFSHashEntry(
                builder,
                sv_to_flatbuf_str(builder, hash_node.name),
                hash_node.is_file,
                hash_to_flatbuf_bytes(builder, hash_node.hash));

            fbvec.push_back(hpfs_fs_entry);
        }
        return builder.CreateVector(fbvec);
    }

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<PeerProperties>>>
    peer_propertiesvector_to_flatbuf_peer_propertieslist(flatbuffers::FlatBufferBuilder &builder, const std::vector<conf::peer_properties> &peers, const std::optional<conf::peer_ip_port> &skipping_ip_port)
    {
        std::vector<flatbuffers::Offset<PeerProperties>> fbvec;
        fbvec.reserve(peers.size());
        for (auto peer : peers)
        {
            // Skipping the requestedc peer from the peer list response.
            if (!skipping_ip_port.has_value() || peer.ip_port != skipping_ip_port.value())
                fbvec.push_back(CreatePeerProperties(
                    builder,
                    sv_to_flatbuf_str(builder, peer.ip_port.host_address),
                    peer.ip_port.port,
                    peer.available_capacity,
                    peer.timestamp));
        }
        return builder.CreateVector(fbvec);
    }

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
    stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::set<std::string> &set)
    {
        std::vector<flatbuffers::Offset<ByteArray>> fbvec;
        fbvec.reserve(set.size());
        for (std::string_view str : set)
            fbvec.push_back(CreateByteArray(builder, sv_to_flatbuf_bytes(builder, str)));
        return builder.CreateVector(fbvec);
    }
}