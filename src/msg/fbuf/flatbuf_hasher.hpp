#ifndef _HP_MSG_FBUF_FBUF_HASHER
#define _HP_MSG_FBUF_FBUF_HASHER

#include "../../pchheader.hpp"
#include "../../util/util.hpp"
#include "p2pmsg_generated.h"

namespace msg::fbuf::p2pmsg
{
    class flatbuf_hasher
    {
    private:
        blake3_hasher hasher;

    public:
        flatbuf_hasher()
        {
            blake3_hasher_init(&hasher);
        }

        void add(const uint8_t i)
        {
            blake3_hasher_update(&hasher, &i, sizeof(uint8_t));
        }

        void add(const uint32_t i)
        {
            uint8_t bytes[4];
            util::uint32_to_bytes(bytes, i);
            blake3_hasher_update(&hasher, bytes, sizeof(bytes));
        }

        void add(const uint64_t i)
        {
            uint8_t bytes[8];
            util::uint64_to_bytes(bytes, i);
            blake3_hasher_update(&hasher, bytes, sizeof(bytes));
        }

        void add(std::string_view sv)
        {
            blake3_hasher_update(&hasher, sv.data(), sv.size());
        }

        void add(const std::set<std::string> &sl)
        {
            for(const std::string &s : sl)
                add(s);
        }

        void add(const flatbuffers::Vector<uint8_t> *v)
        {
            blake3_hasher_update(&hasher, v->data(), v->size());
        }

        void add(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *v)
        {
            for (const auto el : *v)
                add(el->array());
        }

        void add(const util::h32 &h)
        {
            add(h.to_string_view());
        }

        void add(const p2p::sequence_hash &h)
        {
            add(h.seq_no);
            add(h.hash);
        }

        void add(const SequenceHash *h)
        {
            add(h->seq_no());
            add(h->hash());
        }

        const std::string hash()
        {
            std::string hash;
            hash.resize(BLAKE3_OUT_LEN);
            blake3_hasher_finalize(&hasher, reinterpret_cast<uint8_t *>(hash.data()), hash.size());
            return hash;
        }
    };
}

#endif