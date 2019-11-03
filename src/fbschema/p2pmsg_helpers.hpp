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

int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, flatbuffers::uoffset_t content_size);

const p2p::nonunl_proposal create_nonunl_proposal_from_msg(const NonUnl_Proposal_Message &msg, uint64_t timestamp);

const p2p::proposal create_proposal_from_msg(const Proposal_Message &msg, const flatbuffers::Vector<uint8_t> *pubkey, uint64_t timestamp);

//---Message creation helpers---//

void create_msg_from_nonunl_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::nonunl_proposal &nup);

void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p);

void create_containermsg_from_content(
    flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder, bool sign);

//---Conversion helpers from flatbuffers data types to std data types---//

const std::unordered_map<std::string, const std::list<usr::user_submitted_message>>
flatbuf_usermsgsmap_to_usermsgsmap(const flatbuffers::Vector<flatbuffers::Offset<UserSubmittedMessageGroup>> *fbvec);

//---Conversion helpers from std data types to flatbuffers data types---//

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<UserSubmittedMessageGroup>>>
usermsgsmap_to_flatbuf_usermsgsmap(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::list<usr::user_submitted_message>> &map);

} // namespace fbschema::p2pmsg

#endif