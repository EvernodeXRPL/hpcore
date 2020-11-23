#ifndef _HP_UTIL_TTL_SET_
#define _HP_UTIL_TTL_SET_

#include "../pchheader.hpp"

namespace util
{

    /**
     * A string set with expiration for elements.
     */
    class ttl_set
    {
    private:
        // Keeps short-lived items with their absolute expiration time.
        std::unordered_map<std::string, uint64_t> ttlmap;

    public:
        void emplace(const std::string key, const uint64_t ttl_milli);
        void erase(const std::string &key);
        bool exists(const std::string &key);
    };

} // namespace util

#endif