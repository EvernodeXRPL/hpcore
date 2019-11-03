#ifndef _HP_FBSCHEMA_COMMON_HELPERS_
#define _HP_FBSCHEMA_COMMON_HELPERS_

#include "../pchheader.hpp"
#include <flatbuffers/flatbuffers.h>
#include "common_schema_generated.h"

namespace fbschema
{
/**
 * This section contains common Flatbuffer message reading/writing helpers.
 */

//---Conversion helpers from flatbuffers data types to std data types---//

std::string_view flatbuff_bytes_to_sv(const uint8_t *data, flatbuffers::uoffset_t length);

std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer);

const std::set<std::string>
flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec);

const std::unordered_map<std::string, const std::string>
flatbuf_pairvector_to_stringmap(const flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>> *fbvec);

//---Conversion helpers from std data types to flatbuffers data types---//

const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
sv_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv);

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::set<std::string> &set);

const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>>>
stringmap_to_flatbuf_bytepairvector(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::string> &map);

} // namespace fbschema

#endif