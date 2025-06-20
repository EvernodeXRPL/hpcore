#**DEPRECATED:** This file is no longer required as deduplication is handled by bloom filteringand will be removed soon. Please do not use.

#include "rollover_hashset.hpp"

namespace util
{

    rollover_hashset::rollover_hashset(const uint32_t maxsize)
    {
        this->maxsize = maxsize == 0 ? 1 : maxsize;
    }

    /**
     * Inserts the given hash to the list.
     * @return True on succesful insertion. False if hash already exists.
     */
    bool rollover_hashset::try_emplace(const std::string hash)
    {
        const auto itr = recent_hashes.find(hash);
        if (itr == recent_hashes.end()) // Not found
        {
            // Add the new message hash to the set.
            const auto [newitr, success] = recent_hashes.emplace(std::move(hash));

            // Insert a pointer to the stored hash value to the back of the ordered list of hashes.
            recent_hashes_list.push_back(&(*newitr));

            // Remove oldest hash if exceeding max size.
            if (recent_hashes_list.size() > maxsize)
            {
                const std::string &oldest_hash = *recent_hashes_list.front();
                recent_hashes.erase(oldest_hash);
                recent_hashes_list.pop_front();
            }

            return true; // Hash was inserted successfuly.
        }

        return false; // Hash already exists.
    }
}
