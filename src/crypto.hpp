#ifndef _HP_CRYPTO_H_
#define _HP_CRYPTO_H_

/**
 * Offers convenience functions for cryptographic operations wrapping libsodium.
 * These functions are used for contract config and user/peer message authentication.
 */
namespace crypto
{

int init();

void generate_signing_keys(std::string &pubkey, std::string &seckey, std::string &keytype);

std::string sign(std::string_view msg, std::string_view seckey);

std::string sign_b64(std::string_view msg, std::string_view seckeyb64);

int verify(std::string_view msg, std::string_view sig, std::string_view pubkey);

int verify_b64(std::string_view msg, std::string_view sigb64, std::string_view pubkeyb64);

/**
 * Generate SHA 512 hash for message prepend with prefix before hashing.
 * 
 * @param msg message string.
 * @param prefix prefix char array.
 * @param char_length length of prefix char array.
 * @return SHA 512 hash.
 */
std::string sha_512_hash(const std::string &msg, const char *prefix, size_t char_length);

} // namespace crypto

#endif