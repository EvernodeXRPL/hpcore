#ifndef _HASHER_
#define _HASHER_

#include <sodium.h>
#include <iostream>
#include <sstream>

namespace hasher
{

constexpr size_t HASH_SIZE = crypto_generichash_blake2b_BYTES;

struct B2H // blake2b hash is 32 bytes which we store as 4 quad words
{
    uint64_t data[4];
};

// provide some helper functions for working with 32 byte hash type
bool operator==(const B2H &lhs, const B2H &rhs);
bool operator!=(const B2H &lhs, const B2H &rhs);
void operator^=(B2H &lhs, const B2H &rhs);
std::ostream &operator<<(std::ostream &output, const B2H &h);
std::stringstream &operator<<(std::stringstream &output, const B2H &h);

B2H hash(const void *buf1, size_t buf1len, const void *buf2, size_t buf2len);

} // namespace hasher

#endif