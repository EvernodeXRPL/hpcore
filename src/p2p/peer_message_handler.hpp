#ifndef _HP_PEER_MESSAGE_HANDLER_H_
#define _HP_PEER_MESSAGE_HANDLER_H_

#include <string>
#include <flatbuffers/flatbuffers.h>
#include "message_content_generated.h"
#include "message_container_generated.h"
#include "p2p.hpp"

namespace p2p
{
/**
 * This section contains Flatbuffer message reading/writing helpers.
 */

//---Message validation and reading helpers---/

int validate_and_extract_container(const Container **container_ref, std::string_view container_buf);

int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, flatbuffers::uoffset_t content_size);

int validate_content_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp);

const proposal create_proposal_from_msg(const Proposal_Message &msg);

//---Message creation helpers---//

void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const proposal &p);

void create_containermsg_from_content(
    flatbuffers::FlatBufferBuilder &container_builder, const flatbuffers::FlatBufferBuilder &content_builder);

//---Conversion helpers from flatbuffers data types to std data types---//

std::string_view flatbuff_bytes_to_sv(const uint8_t *data, flatbuffers::uoffset_t length);

std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer);

const std::vector<std::string> flatbuf_bytearrayvector_to_vector(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec);

const std::unordered_map<std::string, std::string> flatbuf_pairvector_to_map(const flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>> *fbvec);

//---Conversion helpers from std data types to flatbuffers data types---//

const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
sv_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv);

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
vector_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::vector<std::string> &vec);

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>>>
vector_to_flatbuf_bytepairvector(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, std::string> &map);

} // namespace p2p

#endif