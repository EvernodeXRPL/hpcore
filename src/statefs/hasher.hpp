#ifndef _HASHER_
#define _HASHER_

#include "../pchheader.hpp"

namespace hasher
{

// Hash length (32 bytes)
constexpr size_t HASH_SIZE = crypto_generichash_blake2b_BYTES;

// blake2b hash is 32 bytes which we store as 4 quad words
// Originally from https://github.com/codetsunami/file-ptracer/blob/master/merkle.cpp
struct B2H
{
    uint64_t data[4];

    bool operator==(const B2H rhs) const;
    bool operator!=(const B2H rhs) const;
    void operator^=(const B2H rhs);
};

extern B2H B2H_empty;

std::ostream &operator<<(std::ostream &output, const B2H &h);
std::stringstream &operator<<(std::stringstream &output, const B2H &h);

B2H hash(const void *buf1, const size_t buf1len, const void *buf2, const size_t buf2len);

// Helper class to support std::map/std::unordered_map custom hashing function.
// This is needed to use B2H as the std map container key.
class B2H_std_key_hasher
{
public:
    size_t operator()(const hasher::B2H h) const;
};

} // namespace hasher

#endif