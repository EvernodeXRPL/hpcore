#include "hasher.hpp"

namespace hasher
{

// provide some helper functions for working with 32 byte hash type
bool operator==(const B2H &lhs, const B2H &rhs)
{
    return lhs.data[0] == rhs.data[0] && lhs.data[1] == rhs.data[1] && lhs.data[2] == rhs.data[2] && lhs.data[3] == rhs.data[3];
}

bool operator!=(const B2H &lhs, const B2H &rhs)
{
    return lhs.data[0] != rhs.data[0] || lhs.data[1] != rhs.data[1] || lhs.data[2] != rhs.data[2] || lhs.data[3] != rhs.data[3];
}

void operator^=(B2H &lhs, const B2H &rhs)
{
    lhs.data[0] ^= rhs.data[0];
    lhs.data[1] ^= rhs.data[1];
    lhs.data[2] ^= rhs.data[2];
    lhs.data[3] ^= rhs.data[3];
}

std::ostream &operator<<(std::ostream &output, const B2H &h)
{
    output << h.data[0] << h.data[1] << h.data[2] << h.data[3];
    return output;
}

std::stringstream &operator<<(std::stringstream &output, const B2H &h)
{
    output << std::hex << h;
    return output;
}

// the actual hash function, note that the B2H datatype is always passed by value being only 4 quadwords
B2H hash(const void *buf1, size_t buf1len, const void *buf2, size_t buf2len)
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

} // namespace hasher