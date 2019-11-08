#include "common_helpers.hpp"

namespace fbschema
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
 * Returns return string_view from Flat Buffer vector of bytes.
 */
std::string_view flatbuff_bytes_to_sv(const flatbuffers::Vector<uint8_t> *buffer)
{
    return flatbuff_bytes_to_sv(buffer->Data(), buffer->size());
}

/**
 * Returns set from Flatbuffer vector of ByteArrays.
 */
const std::set<std::string> flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec)
{
    std::set<std::string> set;
    for (auto el : *fbvec)
        set.emplace(std::string(flatbuff_bytes_to_sv(el->array())));
    return set;
}

/**
 * Returns a map from Flatbuffer vector of key value pairs.
 */
const std::unordered_map<std::string, const std::string>
flatbuf_pairvector_to_stringmap(const flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>> *fbvec)
{
    std::unordered_map<std::string, const std::string> map;
    map.reserve(fbvec->size());
    for (auto el : *fbvec)
        map.emplace(flatbuff_bytes_to_sv(el->key()), flatbuff_bytes_to_sv(el->value()));
    return map;
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
 * Returns Flatbuffer vector of ByteArrays from given set of strings.
 */
const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::set<std::string> &set)
{
    std::vector<flatbuffers::Offset<ByteArray>> fbvec;
    fbvec.reserve(set.size());
    for (std::string_view str : set)
        fbvec.push_back(CreateByteArray(builder, sv_to_flatbuff_bytes(builder, str)));
    return builder.CreateVector(fbvec);
}

/**
 * Returns Flatbuffer vector of key value pairs from given map.
 */
const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BytesKeyValuePair>>>
stringmap_to_flatbuf_bytepairvector(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, const std::string> &map)
{
    std::vector<flatbuffers::Offset<BytesKeyValuePair>> fbvec;
    fbvec.reserve(map.size());
    for (auto const &[key, value] : map)
    {
        fbvec.push_back(CreateBytesKeyValuePair(
            builder,
            sv_to_flatbuff_bytes(builder, key),
            sv_to_flatbuff_bytes(builder, value)));
    }
    return builder.CreateVector(fbvec);
}

} // namespace fbschema