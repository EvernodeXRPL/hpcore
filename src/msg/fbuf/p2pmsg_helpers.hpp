#ifndef _HP_MSG_FBUF_P2PMSG_HELPERS_
#define _HP_MSG_FBUF_P2PMSG_HELPERS_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "../../util/h32.hpp"
#include "../../hpfs/hpfs_mount.hpp"
#include "p2pmsg_container_generated.h"
#include "p2pmsg_content_generated.h"

namespace msg::fbuf::p2pmsg
{
    /**
 * This section contains Flatbuffer p2p message reading/writing helpers.
 */

    //---Message validation helpers---/

    int validate_and_extract_container(const Container **container_ref, std::string_view container_buf);

    int validate_container_trust(const Container *container);

    int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, const flatbuffers::uoffset_t content_size);

    //---Message reading helpers---/

    const p2p::peer_challenge get_peer_challenge_from_msg(const Peer_Challenge_Message &msg);

    const p2p::peer_challenge_response create_peer_challenge_response_from_msg(const Peer_Challenge_Response_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey);

    const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnl_Proposal_Message &msg, const uint64_t timestamp);

    const p2p::proposal create_proposal_from_msg(const Proposal_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey, const uint64_t timestamp, const flatbuffers::Vector<uint8_t> *lcl);

    const p2p::history_request create_history_request_from_msg(const History_Request_Message &msg, const flatbuffers::Vector<uint8_t> *lcl);

    const p2p::history_response create_history_response_from_msg(const History_Response_Message &msg);

    const p2p::hpfs_request create_hpfs_request_from_msg(const Hpfs_Request_Message &msg);

    const std::vector<conf::peer_properties> create_peer_list_response_from_msg(const Peer_List_Response_Message &msg);

    //---Message creation helpers---//
    void create_peer_challenge_response_from_challenge(flatbuffers::FlatBufferBuilder &container_builder, const std::string &challenge);

    void create_msg_from_peer_challenge(flatbuffers::FlatBufferBuilder &container_builder, std::string &challenge);

    void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::nonunl_proposal &nup);

    void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p);

    void create_msg_from_history_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_request &hr);

    void create_msg_from_history_response(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_response &hr);

    void create_msg_from_npl_output(flatbuffers::FlatBufferBuilder &container_builder, const std::string_view &msg, std::string_view lcl);

    void create_msg_from_state_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::hpfs_request &hr, std::string_view lcl);

    void create_msg_from_fsentry_response(
        flatbuffers::FlatBufferBuilder &container_builder, const std::string_view path,
        std::vector<hpfs::child_hash_node> &hash_nodes, util::h32 expected_hash, std::string_view lcl);

    void create_msg_from_filehashmap_response(
        flatbuffers::FlatBufferBuilder &container_builder, std::string_view path,
        std::vector<util::h32> &hashmap, std::size_t file_length, util::h32 expected_hash, std::string_view lcl);

    void create_msg_from_block_response(flatbuffers::FlatBufferBuilder &container_builder, p2p::block_response &block_resp, std::string_view lcl);

    void create_containermsg_from_content(
        flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder, std::string_view lcl, const bool sign);

    void create_msg_from_peer_requirement_announcement(flatbuffers::FlatBufferBuilder &container_builder, const bool need_consensus_msg_forwarding, std::string_view lcl);

    void create_msg_from_available_capacity_announcement(flatbuffers::FlatBufferBuilder &container_builder, const int16_t &available_capacity, const uint64_t &timestamp, std::string_view lcl);

    void create_msg_from_peer_list_request(flatbuffers::FlatBufferBuilder &container_builder, std::string_view lcl);

    void create_msg_from_peer_list_response(flatbuffers::FlatBufferBuilder &container_builder, const std::vector<conf::peer_properties> &peers, const std::optional<conf::ip_port_prop> &skipping_ip_port, std::string_view lcl);

    //---Conversion helpers from flatbuffers data types to std data types---//

    const std::unordered_map<std::string, std::list<usr::user_input>>
    flatbuf_user_input_group_to_user_input_map(const flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>> *fbvec);

    //---Conversion helpers from std data types to flatbuffers data types---//

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>>>
    user_input_map_to_flatbuf_user_input_group(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, std::list<usr::user_input>> &map);

    const std::map<uint64_t, const p2p::history_ledger_block>
    flatbuf_historyledgermap_to_historyledgermap(const flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerBlockPair>> *fbvec);

    const std::vector<conf::peer_properties>
    flatbuf_peer_propertieslist_to_peer_propertiesvector(const flatbuffers::Vector<flatbuffers::Offset<Peer_Properties>> *fbvec);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerBlockPair>>>
    historyledgermap_to_flatbuf_historyledgermap(flatbuffers::FlatBufferBuilder &builder, const std::map<uint64_t, const p2p::history_ledger_block> &map);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<Peer_Properties>>>
    peer_propertiesvector_to_flatbuf_peer_propertieslist(flatbuffers::FlatBufferBuilder &builder, const std::vector<conf::peer_properties> &peers, const std::optional<conf::ip_port_prop> &skipping_ip_port);

    void flatbuf_hpfsfshashentry_to_hpfsfshashentry(std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entries,
                                                      const flatbuffers::Vector<flatbuffers::Offset<Hpfs_FS_Hash_Entry>> *fhashes);

    void hpfsfilehash_to_flatbuf_hpfsfilehash(flatbuffers::FlatBufferBuilder &builder, std::vector<flatbuffers::Offset<Hpfs_FS_Hash_Entry>> &list,
                                                std::string_view full_path, bool is_file, std::string_view hash);

    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<Hpfs_FS_Hash_Entry>>>
    hpfsfshashentry_to_flatbuff_hpfsfshashentry(
        flatbuffers::FlatBufferBuilder &builder,
        std::vector<hpfs::child_hash_node> &hash_nodes);

} // namespace msg::fbuf::p2pmsg

#endif
