#include "../pchheader.hpp"
#include "../util/util.hpp"
#include "input_nonce_map.hpp"

namespace usr
{
    constexpr uint64_t TTL = 300000; // 5 minutes.
    constexpr uint16_t CLEANUP_THRESHOLD = 256;

    /**
     * Checks whether the given nonce is valid for the given user pubkey. If it is valid, remembers this nonce
     * to be checked for future checks. (If no_add is true, this nonce will not be remembered)
     */
    bool input_nonce_map::is_valid(const std::string &pubkey, const std::string &nonce, const bool no_add)
    {
        bool valid = false;

        const uint64_t now = util::get_epoch_milliseconds();
        auto itr = nonce_map.find(pubkey);
        if (itr == nonce_map.end())
        {
            valid = true;
            if (!no_add)
                nonce_map.emplace(pubkey, std::pair<std::string, uint64_t>(nonce, util::get_epoch_milliseconds() + TTL));
        }
        else
        {
            const std::string &existing_nonce = itr->second.first;
            const uint64_t expire_on = itr->second.second;
            valid = (expire_on <= now || existing_nonce < nonce);

            if (valid && !no_add)
            {
                itr->second.first = nonce;
                itr->second.second = now + TTL;
            }
        }

        if (nonce_map.size() > CLEANUP_THRESHOLD)
            cleanup();

        return valid;
    }

    void input_nonce_map::cleanup()
    {
        const uint64_t now = util::get_epoch_milliseconds();

        for (auto itr = nonce_map.begin(); itr != nonce_map.end();)
        {
            const uint64_t expire_on = itr->second.second;
            if (expire_on <= now)
                itr = nonce_map.erase(itr);
            else
                itr++;
        }
    }

} // namespace usr
