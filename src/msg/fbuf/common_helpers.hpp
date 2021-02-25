#ifndef _HP_MSG_FBUF_COMMON_HELPERS_
#define _HP_MSG_FBUF_COMMON_HELPERS_

#include "../../pchheader.hpp"
#include "../../util/h32.hpp"
#include "p2pmsg_generated.h"

namespace msg::fbuf
{
    /**
     * This section contains common Flatbuffer message reading/writing helpers.
     */

    //---Flatbuf to std---//

    std::string_view flatbuf_bytes_to_sv(const uint8_t *data, const flatbuffers::uoffset_t length);

    std::string_view flatbuf_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer);

    std::string_view flatbuf_str_to_sv(const flatbuffers::String *buffer);

    util::h32 flatbuf_bytes_to_hash(const flatbuffers::Vector<uint8_t> *buffer);

    std::string_view builder_to_string_view(const flatbuffers::FlatBufferBuilder &builder);

    //---std to Flatbuf---//

    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    sv_to_flatbuf_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv);

    const flatbuffers::Offset<flatbuffers::String>
    sv_to_flatbuf_str(flatbuffers::FlatBufferBuilder &builder, std::string_view sv);

    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    hash_to_flatbuf_bytes(flatbuffers::FlatBufferBuilder &builder, util::h32 hash);

} // namespace msg::fbuf

#endif