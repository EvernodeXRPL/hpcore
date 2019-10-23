#ifndef _HP_PEER_MESSAGE_HANDLER_H_
#define _HP_PEER_MESSAGE_HANDLER_H_

#include <string>
#include <flatbuffers/flatbuffers.h>
#include "message_content_generated.h"
#include "message_container_generated.h"
#include "p2p.hpp"

namespace p2p
{
int validate_and_extract_container(const Container **container_ref, std::string_view container_buf);

int validate_and_extract_content(const Content **content_ref, const uint8_t *content_ptr, flatbuffers::uoffset_t content_size);

bool validate_content_message(std::string_view message, std::string_view signature, std::string_view pubkey, time_t timestamp);

proposal create_proposal_from_msg(const Proposal_Message &msg);

const std::string create_message(flatbuffers::FlatBufferBuilder &container_builder);

std::string_view flatbuff_bytes_to_sv(const uint8_t *data, flatbuffers::uoffset_t length);

std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer);

std::vector<std::string> flatbuf_bytearrayvector_to_vector(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec);

std::unordered_map<std::string, std::string> flatbuf_pairvector_to_map(const flatbuffers::Vector<flatbuffers::Offset<StringKeyValuePair>> *fbvec);

} // namespace p2p

#endif