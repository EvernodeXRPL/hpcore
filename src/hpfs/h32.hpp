#ifndef _HP_HPFS_H32_
#define _HP_HPFS_H32_

#include "../pchheader.hpp"

namespace hpfs
{

    // blake2b hash is 32 bytes which we store as 4 quad words
    // Originally from https://github.com/codetsunami/file-ptracer/blob/master/merkle.cpp
    struct h32
    {
        uint64_t data[4];

        bool operator==(const h32 rhs) const;
        bool operator!=(const h32 rhs) const;
        void operator^=(const h32 rhs);
        std::string_view to_string_view() const;
        h32 &operator=(std::string_view sv);
        h32 &operator=(std::string s);
        bool operator<(const h32 rhs) const;

        h32()
        {
            memset(data, 0, sizeof(data));
        }
    };
    extern h32 h32_empty;

    std::ostream &operator<<(std::ostream &output, const h32 &h);

    // Helper class to support std::map/std::unordered_map custom hashing function.
    // This is needed to use B2H as the std map container key.
    class h32_std_key_hasher
    {
    public:
        size_t operator()(const h32 h) const;
    };

} // namespace hpfs

#endif