#include "common_helpers.hpp"

namespace msg::fbuf
{

    //---Conversion helpers from flatbuffers data types to std data types---//

    /**
 * Returns string_view from flat buffer data pointer and length.
 */
    std::string_view flatbuff_bytes_to_sv(const uint8_t *data, const flatbuffers::uoffset_t length)
    {
        const char *signature_content_str = reinterpret_cast<const char *>(data);
        return std::string_view(signature_content_str, length);
    }

    /**
 * Returns string_view from Flat Buffer vector of bytes.
 */
    std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer)
    {
        return flatbuff_bytes_to_sv(buffer->Data(), buffer->size());
    }

    /**
 * Returns return string_view from Flat Buffer string.
 */
    std::string_view flatbuff_str_to_sv(const flatbuffers::String *buffer)
    {
        return flatbuff_bytes_to_sv(buffer->Data(), buffer->size());
    }

    /**
 * Returns hash from Flat Buffer vector of bytes.
 */
    util::h32 flatbuff_bytes_to_hash(const flatbuffers::Vector<uint8_t> *buffer)
    {
        return *reinterpret_cast<const util::h32 *>(buffer->data());
    }

    //---Conversion helpers from std data types to flatbuffers data types---//
    //---These are used in constructing Flatbuffer messages using builders---//

    /**
 * Returns Flatbuffer bytes vector from string_view.
 */
    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    sv_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv)
    {
        return builder.CreateVector(reinterpret_cast<const uint8_t *>(sv.data()), sv.size());
    }

    /**
 * Returns Flatbuffer string from string_view.
 */
    const flatbuffers::Offset<flatbuffers::String>
    sv_to_flatbuff_str(flatbuffers::FlatBufferBuilder &builder, std::string_view sv)
    {
        return builder.CreateString(sv);
    }

    /**
 * Returns Flatbuffer bytes vector from hash.
 */
    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    hash_to_flatbuff_bytes(flatbuffers::FlatBufferBuilder &builder, const util::h32 hash)
    {
        return builder.CreateVector(reinterpret_cast<const uint8_t *>(&hash), sizeof(util::h32));
    }

} // namespace msg::fbuf