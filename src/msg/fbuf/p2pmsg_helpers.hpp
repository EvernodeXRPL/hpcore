#ifndef _HP_MSG_FBUF_P2PMSG_HELPERS_
#define _HP_MSG_FBUF_P2PMSG_HELPERS_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "../../hpfs/h32.hpp"
#include "../../hpfs/hpfs.hpp"
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

    const std::string_view get_peer_challenge_from_msg(const Peer_Challenge_Message &msg);

    const p2p::peer_challenge_response create_peer_challenge_response_from_msg(const Peer_Challenge_Response_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey);

    const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnl_Proposal_Message &msg, const uint64_t timestamp);

    const p2p::proposal create_proposal_from_msg(const Proposal_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey, const uint64_t timestamp, const flatbuffers::Vector<uint8_t> *lcl);

    const p2p::history_request create_history_request_from_msg(const History_Request_Message &msg);

    const p2p::history_response create_history_response_from_msg(const History_Response_Message &msg);

    const p2p::state_request create_state_request_from_msg(const State_Request_Message &msg);

    //---Message creation helpers---//
    void create_peer_challenge_response_from_challenge(flatbuffers::FlatBufferBuilder &container_builder, const std::string &challenge);

    void create_msg_from_peer_challenge(flatbuffers::FlatBufferBuilder &container_builder, std::string &challenge);

    void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::nonunl_proposal &nup);

    void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p);

    void create_msg_from_history_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_request &hr);

    void create_msg_from_history_response(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_response &hr);

    void create_msg_from_npl_output(flatbuffers::FlatBufferBuilder &container_builder, const std::string_view &msg, std::string_view lcl);

    void create_msg_from_state_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::state_request &hr, std::string_view lcl);

    void create_msg_from_fsentry_response(
        flatbuffers::FlatBufferBuilder &container_builder, const std::string_view path,
        std::vector<hpfs::child_hash_node> &hash_nodes, hpfs::h32 expected_hash, std::string_view lcl);

    void create_msg_from_filehashmap_response(
        flatbuffers::FlatBufferBuilder &container_builder, std::string_view path,
        std::vector<hpfs::h32> &hashmap, std::size_t file_length, hpfs::h32 expected_hash, std::string_view lcl);

    void create_msg_from_block_response(flatbuffers::FlatBufferBuilder &container_builder, p2p::block_response &block_resp, std::string_view lcl);

    void create_containermsg_from_content(
        flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder, std::string_view lcl, const bool sign);

    //---Conversion helpers from flatbuffers data types to std data types---//

    const std::unordered_map<std::string, const std::list<usr::user_input>>
    flatbuf_user_input_group_to_user_input_map(const flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>> *fbvec);

    //---Conversion helpers from std data types to flatbuffers data types---//

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserInputGroup>>>
    user_input_map_to_flatbuf_user_input_group(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::list<usr::user_input>> &map);

    const std::map<uint64_t, const p2p::history_ledger>
    flatbuf_historyledgermap_to_historyledgermap(const flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerPair>> *fbvec);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerPair>>>
    historyledgermap_to_flatbuf_historyledgermap(flatbuffers::FlatBufferBuilder &builder, const std::map<uint64_t, const p2p::history_ledger> &map);

    void flatbuf_statefshashentry_to_statefshashentry(std::unordered_map<std::string, p2p::state_fs_hash_entry> &fs_entries,
                                                      const flatbuffers::Vector<flatbuffers::Offset<State_FS_Hash_Entry>> *fhashes);

    void statefilehash_to_flatbuf_statefilehash(flatbuffers::FlatBufferBuilder &builder, std::vector<flatbuffers::Offset<State_FS_Hash_Entry>> &list,
                                                std::string_view full_path, bool is_file, std::string_view hash);

    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<State_FS_Hash_Entry>>>
    statefshashentry_to_flatbuff_statefshashentry(
        flatbuffers::FlatBufferBuilder &builder,
        std::vector<hpfs::child_hash_node> &hash_nodes);

    void create_msg_for_connected_status_announcement(flatbuffers::FlatBufferBuilder &container_builder, const bool is_weakly_connected, std::string_view lcl);

} // namespace msg::fbuf::p2pmsg

#endif
