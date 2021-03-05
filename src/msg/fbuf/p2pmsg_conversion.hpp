#ifndef _HP_MSG_FBUF_P2PMSG_CONVERSION_
#define _HP_MSG_FBUF_P2PMSG_CONVERSION_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "../../hpfs/hpfs_mount.hpp"
#include "p2pmsg_generated.h"

namespace msg::fbuf::p2pmsg
{

    //---Flatbuf to std---//

    bool verify_peer_message(std::string_view message);

    const p2p::peer_message_info get_peer_message_info(std::string_view message);

    bool verify_proposal_msg_trust(const p2p::peer_message_info &mi);

    bool verify_npl_msg_trust(const p2p::peer_message_info &mi);

    const p2p::peer_challenge create_peer_challenge_from_msg(const p2p::peer_message_info &mi);

    const p2p::peer_challenge_response create_peer_challenge_response_from_msg(const p2p::peer_message_info &mi);

    const p2p::proposal create_proposal_from_msg(const p2p::peer_message_info &mi);

    const p2p::npl_message create_npl_from_msg(const p2p::peer_message_info &mi);

    const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const p2p::peer_message_info &mi);

    const std::vector<p2p::peer_properties> create_peer_list_response_from_msg(const p2p::peer_message_info &mi);

    const p2p::peer_capacity_announcement create_peer_capacity_announcement_from_msg(const p2p::peer_message_info &mi);

    const p2p::peer_requirement_announcement create_peer_requirement_announcement_from_msg(const p2p::peer_message_info &mi);

    const p2p::hpfs_request create_hpfs_request_from_msg(const p2p::peer_message_info &mi);

    p2p::sequence_hash flatbuf_seqhash_to_seqhash(const msg::fbuf::p2pmsg::SequenceHash *fbseqhash);

    const std::set<std::string> flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec);

    const std::unordered_map<std::string, std::list<usr::submitted_user_input>>
    flatbuf_user_input_group_to_user_input_map(const flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>> *fbvec);

    void flatbuf_hpfsfshashentry_to_hpfsfshashentry(std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entries, const flatbuffers::Vector<flatbuffers::Offset<HpfsFSHashEntry>> *fhashes);

    const std::vector<p2p::peer_properties>
    flatbuf_peer_propertieslist_to_peer_propertiesvector(const flatbuffers::Vector<flatbuffers::Offset<PeerProperties>> *fbvec);

    //---std to Flatbuf---//

    const std::string generate_proposal_signature(const p2p::proposal &p);

    const std::string generate_npl_signature(std::string_view data, const p2p::sequence_hash &lcl_id);

    void create_p2p_msg(flatbuffers::FlatBufferBuilder &builder, const msg::fbuf::p2pmsg::P2PMsgContent content_type, const flatbuffers::Offset<void> content);

    void create_msg_from_peer_challenge(flatbuffers::FlatBufferBuilder &builder, std::string &challenge);

    void create_peer_challenge_response_from_challenge(flatbuffers::FlatBufferBuilder &builder, const std::string &challenge);

    void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::nonunl_proposal &nup);

    void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p);

    void create_msg_from_npl_output(flatbuffers::FlatBufferBuilder &builder, std::string_view data, const p2p::sequence_hash &lcl_id);

    void create_msg_from_hpfs_request(flatbuffers::FlatBufferBuilder &builder, const p2p::hpfs_request &hr);

    void create_msg_from_fsentry_response(
        flatbuffers::FlatBufferBuilder &builder, const std::string_view path, const uint32_t mount_id, const mode_t dir_mode,
        std::vector<hpfs::child_hash_node> &hash_nodes, const util::h32 &expected_hash);

    void create_msg_from_filehashmap_response(
        flatbuffers::FlatBufferBuilder &builder, std::string_view path, const uint32_t mount_id,
        std::vector<util::h32> &hashmap, const std::size_t file_length, const mode_t file_mode, const util::h32 &expected_hash);

    void create_msg_from_block_response(flatbuffers::FlatBufferBuilder &builder, p2p::block_response &block_resp, const uint32_t mount_id);

    void create_msg_from_peer_requirement_announcement(flatbuffers::FlatBufferBuilder &builder, const bool need_consensus_msg_forwarding);

    void create_msg_from_available_capacity_announcement(flatbuffers::FlatBufferBuilder &builder, const int16_t &available_capacity, const uint64_t &timestamp);

    void create_msg_from_peer_list_request(flatbuffers::FlatBufferBuilder &builder);

    void create_msg_from_peer_list_response(flatbuffers::FlatBufferBuilder &builder, const std::vector<p2p::peer_properties> &peers, const std::optional<conf::peer_ip_port> &skipping_ip_port);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>>>
    user_input_map_to_flatbuf_user_input_group(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, std::list<usr::submitted_user_input>> &map);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<HpfsFSHashEntry>>>
    hpfsfshashentry_to_flatbuf_hpfsfshashentry(
        flatbuffers::FlatBufferBuilder &builder,
        std::vector<hpfs::child_hash_node> &hash_nodes);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<PeerProperties>>>
    peer_propertiesvector_to_flatbuf_peer_propertieslist(flatbuffers::FlatBufferBuilder &builder, const std::vector<p2p::peer_properties> &peers, const std::optional<conf::peer_ip_port> &skipping_ip_port);

    const flatbuffers::Offset<msg::fbuf::p2pmsg::SequenceHash>
    seqhash_to_flatbuf_seqhash(flatbuffers::FlatBufferBuilder &builder, const p2p::sequence_hash &seqhash);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
    stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::set<std::string> &set);
}

#endif
