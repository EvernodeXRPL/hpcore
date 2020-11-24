#include "ttl_set.hpp"
#include "util.hpp"

namespace util
{

    /**
     * If key does not exist, inserts it with the specified ttl. If key exists,
     * renews the expiration time to match the time-to-live from now onwards.
     * @param key Object to insert.
     * @param ttl Time to live in milliseonds.
     */
    void ttl_set::emplace(const std::string key, const uint64_t ttl_milli)
    {
        ttlmap[key] = util::get_epoch_milliseconds() + ttl_milli;
    }

    void ttl_set::erase(const std::string &key)
    {
        const auto itr = ttlmap.find(key);
        if (itr != ttlmap.end())
            ttlmap.erase(itr);
    }

    /**
     * Returns true of the key exists and not expired. Returns false if key does not exist
     * or has expired.
     */
    bool ttl_set::exists(const std::string &key)
    {
        const auto itr = ttlmap.find(key);
        if (itr == ttlmap.end()) // Not found
            return false;

        // Check whether we are passed the expiration time (itr->second is the expiration time)
        const bool expired = util::get_epoch_milliseconds() > itr->second;
        if (expired)
            ttlmap.erase(itr);

        return !expired;
    }

} // namespace util