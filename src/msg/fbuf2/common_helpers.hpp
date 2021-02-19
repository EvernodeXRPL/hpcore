#ifndef _HP_MSG_FBUF_COMMON_HELPERS_
#define _HP_MSG_FBUF_COMMON_HELPERS_

#include "../../pchheader.hpp"
#include "../../util/h32.hpp"

namespace msg::fbuf2
{
    /**
     * This section contains common Flatbuffer message reading/writing helpers.
     */

    //---Conversion helpers from flatbuffers data types to std data types---//

    std::string_view flatbuff_bytes_to_sv(const uint8_t *data, const flatbuffers::uoffset_t length);

    std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer);

    std::string_view flatbuff_str_to_sv(const flatbuffers::String *buffer);

    util::h32 flatbuff_bytes_to_hash(const flatbuffers::Vector<uint8_t> *buffer);

    const std::set<std::string>
    flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec);

    //---Conversion helpers from std data types to flatbuffers data types---//

    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    sv_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv);

    const flatbuffers::Offset<flatbuffers::String>
    sv_to_flatbuff_str(flatbuffers::FlatBufferBuilder &builder, std::string_view sv);

    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    hash_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, util::h32 hash);

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
    stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::set<std::string> &set);

} // namespace msg::fbuf

#endif