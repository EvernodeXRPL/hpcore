#ifndef _HP_FBSCHEMA_P2PMSG_HELPERS_
#define _HP_FBSCHEMA_P2PMSG_HELPERS_

#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"
#include "p2pmsg_container_generated.h"
#include "p2pmsg_content_generated.h"
#include "../p2p/p2p.hpp"

namespace fbschema::p2pmsg
{
/**
 * This section contains Flatbuffer p2p message reading/writing helpers.
 */

//---Message validation and reading helpers---/

int validate_and_extract_container(const Container **container_ref, std::string_view container_buf);

int validate_container_trust(const Container *container);

int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, const flatbuffers::uoffset_t content_size);

const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnl_Proposal_Message &msg, const uint64_t timestamp);

const p2p::proposal create_proposal_from_msg(const Proposal_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey, const uint64_t timestamp, const flatbuffers::Vector<uint8_t> *lcl);

const p2p::history_request create_history_request_from_msg(const History_Request_Message &msg);

const p2p::history_response create_history_response_from_msg(const History_Response_Message &msg);

const p2p::state_request create_state_request_from_msg(const State_Request_Message &msg);

//---Message creation helpers---//

void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::nonunl_proposal &nup);

void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p);

void create_msg_from_history_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_request &hr);

void create_msg_from_history_response(flatbuffers::FlatBufferBuilder &container_builder, const p2p::history_response &hr);

void create_msg_from_npl_output(flatbuffers::FlatBufferBuilder &container_builder, const p2p::npl_message &npl, std::string_view lcl);

void create_msg_from_state_request(flatbuffers::FlatBufferBuilder &container_builder, const p2p::state_request &hr, std::string_view lcl);

void create_containermsg_from_content(
    flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder, std::string_view lcl, const bool sign);

//---Conversion helpers from flatbuffers data types to std data types---//

const std::unordered_map<std::string, const std::list<usr::user_submitted_message>>
flatbuf_usermsgsmap_to_usermsgsmap(const flatbuffers::Vector<flatbuffers::Offset<UserSubmittedMessageGroup>> *fbvec);

//---Conversion helpers from std data types to flatbuffers data types---//

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserSubmittedMessageGroup>>>
usermsgsmap_to_flatbuf_usermsgsmap(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::list<usr::user_submitted_message>> &map);

const std::map<uint64_t, const p2p::history_ledger>
flatbuf_historyledgermap_to_historyledgermap(const flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerPair>> *fbvec);

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<HistoryLedgerPair>>>
historyledgermap_to_flatbuf_historyledgermap(flatbuffers::FlatBufferBuilder &builder, const std::map<uint64_t, const p2p::history_ledger> &map);

std::unordered_map<std::string, p2p::state_fs_hash_entry>
flatbuf_statefshashentry_to_statefshashentry(const flatbuffers::Vector<flatbuffers::Offset<State_FS_Hash_Entry>> *fhashes);

void statefilehash_to_flatbuf_statefilehash(flatbuffers::FlatBufferBuilder &builder, std::vector<flatbuffers::Offset<State_FS_Hash_Entry>> &list,
                                            std::string_view full_path, bool is_file, std::string_view hash);

flatbuffers::Offset<Content_Response>
create_msg_from_content_response(flatbuffers::FlatBufferBuilder &builder, const std::string &fullpath, std::vector<flatbuffers::Offset<State_FS_Hash_Entry>> &content);

} // namespace fbschema::p2pmsg

#endif