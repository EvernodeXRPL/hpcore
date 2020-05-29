#include "h32.hpp"

/**
 * Based on https://github.com/codetsunami/file-ptracer/blob/master/merkle.cpp
 */
namespace hpfs
{
    /**
     * Helper functions for working with 32 byte hash type h32.
     */

    h32 h32_empty;

    bool h32::operator==(const h32 rhs) const
    {
        return this->data[0] == rhs.data[0] && this->data[1] == rhs.data[1] && this->data[2] == rhs.data[2] && this->data[3] == rhs.data[3];
    }

    bool h32::operator!=(const h32 rhs) const
    {
        return this->data[0] != rhs.data[0] || this->data[1] != rhs.data[1] || this->data[2] != rhs.data[2] || this->data[3] != rhs.data[3];
    }

    void h32::operator^=(const h32 rhs)
    {
        this->data[0] ^= rhs.data[0];
        this->data[1] ^= rhs.data[1];
        this->data[2] ^= rhs.data[2];
        this->data[3] ^= rhs.data[3];
    }

    std::ostream &operator<<(std::ostream &output, const h32 &h)
    {
        const uint8_t *buf = reinterpret_cast<const uint8_t *>(&h);
        for (int i = 0; i < sizeof(h32); i++)
            output << std::hex << std::setfill('0') << std::setw(2) << (int)buf[i];

        return output;
    }

    // Helper class to support std::map/std::unordered_map custom hashing function.
    // This is needed to use B2H as the std map container key.
    size_t h32_std_key_hasher::operator()(const h32 h) const
    {
        // Compute individual hash values. http://stackoverflow.com/a/1646913/126995
        size_t res = 17;
        res = res * 31 + std::hash<uint64_t>()(h.data[0]);
        res = res * 31 + std::hash<uint64_t>()(h.data[1]);
        res = res * 31 + std::hash<uint64_t>()(h.data[2]);
        res = res * 31 + std::hash<uint64_t>()(h.data[3]);
        return res;
    }

} // namespace hpfs