#**DEPRECATED:** This file is no longer required as deduplication is handled by bloom filteringand will be removed soon. Please do not use.

#ifndef _HP_UTIL_ROLLOVER_HASHSET_
#define _HP_UTIL_ROLLOVER_HASHSET_

#include "../pchheader.hpp"

namespace util
{

    /**
     * FIFO hash set with a max size.
     */
    class rollover_hashset
    {
    private:
        // The set of recent hashes used for duplicate detection.
        std::unordered_set<std::string> recent_hashes;

        // The supporting list of recent hashes used for adding and removing hashes from
        // the 'recent_hashes' in a first-in-first-out manner.
        std::list<const std::string *> recent_hashes_list;

        uint32_t maxsize;

    public:
        rollover_hashset(const uint32_t maxsize);
        bool try_emplace(const std::string hash);
    };
} // namespace util

#endif
