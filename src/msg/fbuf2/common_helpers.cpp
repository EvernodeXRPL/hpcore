#include "common_helpers.hpp"

namespace msg::fbuf2
{

    //---Flatbuf to std---//

    std::string_view flatbuf_bytes_to_sv(const uint8_t *data, const flatbuffers::uoffset_t length)
    {
        const char *signature_content_str = reinterpret_cast<const char *>(data);
        return std::string_view(signature_content_str, length);
    }

    std::string_view flatbuf_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer)
    {
        return flatbuf_bytes_to_sv(buffer->Data(), buffer->size());
    }

    std::string_view flatbuf_str_to_sv(const flatbuffers::String *buffer)
    {
        return flatbuf_bytes_to_sv(buffer->Data(), buffer->size());
    }

    util::h32 flatbuf_bytes_to_hash(const flatbuffers::Vector<uint8_t> *buffer)
    {
        return *reinterpret_cast<const util::h32 *>(buffer->data());
    }

    std::string_view builder_to_string_view(const flatbuffers::FlatBufferBuilder &builder)
    {
        std::string_view msg = std::string_view(
            reinterpret_cast<const char *>(builder.GetBufferPointer()), builder.GetSize());
        return msg;
    }

    //---std to Flatbuf---//

    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    sv_to_flatbuf_bytes(flatbuffers::FlatBufferBuilder &builder, std::string_view sv)
    {
        return builder.CreateVector(reinterpret_cast<const uint8_t *>(sv.data()), sv.size());
    }

    const flatbuffers::Offset<flatbuffers::String>
    sv_to_flatbuf_str(flatbuffers::FlatBufferBuilder &builder, std::string_view sv)
    {
        return builder.CreateString(sv);
    }

    const flatbuffers::Offset<flatbuffers::Vector<uint8_t>>
    hash_to_flatbuf_bytes(flatbuffers::FlatBufferBuilder &builder, const util::h32 hash)
    {
        return builder.CreateVector(reinterpret_cast<const uint8_t *>(&hash), sizeof(util::h32));
    }

} // namespace msg::fbuf