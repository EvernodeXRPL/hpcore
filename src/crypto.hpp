#ifndef _HP_CRYPTO_
#define _HP_CRYPTO_

#include "pchheader.hpp"

/**
 * Offers convenience functions for cryptographic operations wrapping libsodium.
 * These functions are used for contract config and user/peer message authentication.
 */
namespace crypto
{

    // Prefix byte to append to ed25519 keys.
    static unsigned char KEYPFX_ed25519 = 0xED;
    // Prefixed public key bytes.
    static size_t PFXD_PUBKEY_BYTES = crypto_sign_ed25519_PUBLICKEYBYTES + 1;
    // Prefixed secret key bytes.
    static size_t PFXD_SECKEY_BYTES = crypto_sign_ed25519_SECRETKEYBYTES + 1;

    int init();

    void generate_signing_keys(std::string &pubkey, std::string &seckey);

    std::string sign(std::string_view msg, std::string_view seckey);

    std::string sign_hex(std::string_view msg, std::string_view seckeyhex);

    int verify(std::string_view msg, std::string_view sig, std::string_view pubkey);

    int verify_hex(std::string_view msg, std::string_view sighex, std::string_view pubkeyhex);

    void random_bytes(std::string &result, const size_t len);

    std::string get_hash(std::string_view data);

    std::string get_hash(const unsigned char *data, size_t data_length);

    std::string get_hash(std::string_view s1, std::string_view s2);

    std::string get_hash(const std::vector<std::string_view> &sw_vect);

} // namespace crypto

#endif