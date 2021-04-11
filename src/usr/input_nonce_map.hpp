#ifndef _HP_USR_INPUT_NONCE_MAP_
#define _HP_USR_INPUT_NONCE_MAP_

#include "../pchheader.hpp"

namespace usr
{
    class input_nonce_map
    {
    private:
        // Keeps short-lived nonces and signatures with their absolute expiration time.
        // Keyed by user binary pubkey.
        std::unordered_map<std::string, std::tuple<uint64_t, std::string, uint64_t>> nonce_map;
        void cleanup();

    public:
        int check(const std::string &pubkey, const uint64_t &nonce, const std::string &sig, const uint64_t &max_ledger_seq_no, const bool no_add = false);
    };

} // namespace usr

#endif