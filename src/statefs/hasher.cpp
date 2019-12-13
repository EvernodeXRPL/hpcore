#include "hasher.hpp"

/**
 * Contains hashing functions and helpers used to manipulate block hashes used in state management.
 * This could also be used throughout rest of the application as well. However for now we are only
 * using this for state management code base only.
 * 
 * Based on https://github.com/codetsunami/file-ptracer/blob/master/merkle.cpp
 */
namespace hasher
{

// Represents empty/default B2H hash value.
B2H B2H_empty = hasher::B2H_empty;

/**
 * Helper functions for working with 32 byte hash type B2H.
 */

bool B2H::operator==(const B2H rhs) const
{
    return this->data[0] == rhs.data[0] && this->data[1] == rhs.data[1] && this->data[2] == rhs.data[2] && this->data[3] == rhs.data[3];
}

bool B2H::operator!=(const B2H rhs) const
{
    return this->data[0] != rhs.data[0] || this->data[1] != rhs.data[1] || this->data[2] != rhs.data[2] || this->data[3] != rhs.data[3];
}

void B2H::operator^=(const B2H rhs)
{
    this->data[0] ^= rhs.data[0];
    this->data[1] ^= rhs.data[1];
    this->data[2] ^= rhs.data[2];
    this->data[3] ^= rhs.data[3];
}

std::ostream &operator<<(std::ostream &output, const B2H &h)
{
    output << h.data[0];// << h.data[1] << h.data[2] << h.data[3];
    return output;
}

std::stringstream &operator<<(std::stringstream &output, const B2H &h)
{
    output << std::hex << h;
    return output;
}

// The actual hash function, note that the B2H datatype is always passed by value being only 4 quadwords.
// This function accepts two buffers to hash together in order to support common use case in state handling.
B2H hash(const void *buf1, const size_t buf1len, const void *buf2, const size_t buf2len)
{
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, NULL, 0, HASH_SIZE);

    crypto_generichash_blake2b_update(&state,
                                      reinterpret_cast<const unsigned char *>(buf1), buf1len);
    crypto_generichash_blake2b_update(&state,
                                      reinterpret_cast<const unsigned char *>(buf2), buf2len);
    B2H ret;
    crypto_generichash_blake2b_final(
        &state,
        reinterpret_cast<unsigned char *>(&ret),
        HASH_SIZE);
    return ret;
}

// Helper class to support std::map/std::unordered_map custom hashing function.
// This is needed to use B2H as the std map container key.
size_t B2H_std_key_hasher::operator()(const hasher::B2H h) const
{
    // Compute individual hash values. http://stackoverflow.com/a/1646913/126995
    size_t res = 17;
    res = res * 31 + std::hash<uint64_t>()(h.data[0]);
    res = res * 31 + std::hash<uint64_t>()(h.data[1]);
    res = res * 31 + std::hash<uint64_t>()(h.data[2]);
    res = res * 31 + std::hash<uint64_t>()(h.data[3]);
    return res;
}

} // namespace hasher