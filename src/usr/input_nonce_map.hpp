#ifndef _HP_USR_INPUT_NONCE_MAP_
#define _HP_USR_INPUT_NONCE_MAP_

#include "../pchheader.hpp"

namespace usr
{
    class input_nonce_map
    {
    private:
        // Keeps short-lived items with their absolute expiration time.
        std::unordered_map<std::string, std::pair<std::string, uint64_t>> nonce_map;
        void cleanup();

    public:
        bool is_valid(const std::string &pubkey, const std::string &nonce);
    };

} // namespace usr

#endif