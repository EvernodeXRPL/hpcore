#ifndef _HP_CRYPTO_
#define _HP_CRYPTO_

#include "pchheader.hpp"

/**
 * Offers convenience functions for cryptographic operations wrapping libsodium.
 * These functions are used for config and user/peer message authentication.
 */
namespace crypto
{

    // Prefix byte to append to ed25519 keys.
    constexpr const unsigned char KEYPFX_ed25519 = 0xED;

    int init();

    void generate_signing_keys(std::string &pubkey, std::string &seckey);

    const std::string sign(std::string_view msg, std::string_view seckey);

    int verify(std::string_view msg, std::string_view sig, std::string_view pubkey);

    void random_bytes(std::string &result, const size_t len);

    const std::string get_hash(std::string_view data);

    const std::string get_hash(const void *data, const size_t data_length);

    const std::string get_hash(std::string_view s1, std::string_view s2);

    template <typename T>
    const std::string get_list_hash(const T &str_list);

    const std::string generate_uuid();

} // namespace crypto

#endif