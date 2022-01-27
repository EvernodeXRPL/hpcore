#include "../pchheader.hpp"
#include "../util/util.hpp"
#include "../ledger/ledger.hpp"
#include "input_nonce_map.hpp"

namespace usr
{
    constexpr uint64_t TTL = 300000; // 5 minutes.
    constexpr uint16_t CLEANUP_THRESHOLD = 256;

    /**
     * Checks whether the given nonce is valid for the given user pubkey. If it is valid, remembers this nonce
     * to be checked for future checks. (If no_add is true, this nonce will not be remembered)
     * @return 0 if nonce is valid to be submitted.
     *         1 if nonce has expired.
     *         2 if message with same nonce/sig has already been submitted.
     */
    int input_nonce_map::check(const std::string &pubkey, const uint64_t &nonce, const std::string &sig, const uint64_t &max_ledger_seq_no, const bool no_add)
    {
        int result = 0;
        
        auto itr = nonce_map.find(pubkey);
        if (itr == nonce_map.end())
        {
            result = 0;
            if (!no_add)
                nonce_map.emplace(pubkey, std::tuple<uint64_t, std::string, uint64_t>(nonce, sig, max_ledger_seq_no));
        }
        else
        {
            const uint64_t &existing_nonce = std::get<0>(itr->second);
            const uint64_t expire_lcl_seq_no = std::get<2>(itr->second);

            // Check if previous nonce has already expired or it is less than new nonce.
            if (expire_lcl_seq_no <= ledger::ctx.get_lcl_id().seq_no || existing_nonce < nonce)
            {
                if (!no_add)
                {
                    std::get<0>(itr->second) = nonce;
                    std::get<2>(itr->second) = max_ledger_seq_no;
                }
                result = 0;
            }
            else
            {
                // If new nonce is deemed invalid, check if new nonce/sig is same as old nonce/sig.
                const std::string &existing_sig = std::get<1>(itr->second);
                result = (existing_nonce == nonce && existing_sig == sig) ? 2 : 1;
            }
        }

        if (nonce_map.size() > CLEANUP_THRESHOLD)
            cleanup();

        return result;
    }

    void input_nonce_map::cleanup()
    {
        const uint64_t now = util::get_epoch_milliseconds();

        for (auto itr = nonce_map.begin(); itr != nonce_map.end();)
        {
            const uint64_t expire_on = std::get<2>(itr->second);
            if (expire_on <= now)
                itr = nonce_map.erase(itr);
            else
                itr++;
        }
    }

} // namespace usr
