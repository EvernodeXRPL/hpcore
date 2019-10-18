#include <cstdio>
#include <iostream>
#include "crypto.hpp"
#include "util.hpp"
#include <boost/beast/core.hpp>

namespace crypto
{

/**
 * Initializes the crypto subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
int init()
{
    if (sodium_init() < 0)
    {
        std::cerr << "sodium_init failed.\n";
        return -1;
    }

    return 0;
}

/**
 * Generates a signing key pair using libsodium and assigns them to the provided strings.
 */
void generate_signing_keys(std::string &pubkey, std::string &seckey, std::string &keytype)
{
    // Generate key pair using libsodium default algorithm.
    // Currently using ed25519. So append prefix byte to represent that.

    pubkey.resize(PFXD_PUBKEY_BYTES);
    pubkey[0] = KEYPFX_ed25519;

    seckey.resize(PFXD_SECKEY_BYTES);
    seckey[0] = KEYPFX_ed25519;

    crypto_sign_keypair(
        reinterpret_cast<unsigned char *>(pubkey.data() + 1),
        reinterpret_cast<unsigned char *>(seckey.data() + 1));

    keytype = crypto_sign_primitive();
}

/**
 * Returns the signature bytes for a message.
 * 
 * @param msg Message bytes to sign.
 * @param seckey Secret key bytes.
 * @return Signature bytes.
 */
std::string sign(std::string_view msg, std::string_view seckey)
{
    //Generate the signature using libsodium.

    std::string sig;
    sig.resize(crypto_sign_BYTES);
    crypto_sign_detached(
        reinterpret_cast<unsigned char *>(sig.data()),
        NULL,
        reinterpret_cast<const unsigned char *>(msg.data()),
        msg.length(),
        reinterpret_cast<const unsigned char *>(seckey.data() + 1)); // +1 to skip the prefix byte.
    
    return sig;
}

/**
 * Returns the hex signature string for a message.
 * 
 * @param msg Message bytes to sign.
 * @param seckeyhex hex secret key string.
 * @return hex signature string.
 */
std::string sign_hex(std::string_view msg, std::string_view seckeyhex)
{
    //Decode hex string and generate the signature using libsodium.

    unsigned char seckey[PFXD_SECKEY_BYTES];
    util::hex2bin(seckey, PFXD_SECKEY_BYTES, seckeyhex);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(
        sig,
        NULL,
        reinterpret_cast<const unsigned char *>(msg.data()),
        msg.length(),
        seckey + 1); // +1 to skip prefix byte.

    std::string sighex;
    util::bin2hex(sighex, sig, crypto_sign_BYTES);
    return sighex;
}

/**
 * Verifies the given signature bytes for the message.
 * 
 * @param msg Message bytes.
 * @param sig Signature bytes.
 * @param pubkey Public key bytes.
 * @return 0 for successful verification. -1 for failure.
 */
int verify(std::string_view msg, std::string_view sig, std::string_view pubkey)
{
    return crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char *>(sig.data()),
        reinterpret_cast<const unsigned char *>(msg.data()),
        msg.length(),
        reinterpret_cast<const unsigned char *>(pubkey.data() + 1)); // +1 to skip prefix byte.
}

/**
 * Verifies the given hex signature for the message.
 * 
 * @param msg hex message string.
 * @param sighex hex signature string.
 * @param pubkeyhex hex secret key.
 * @return 0 for successful verification. -1 for failure.
 */
int verify_hex(std::string_view msg, std::string_view sighex, std::string_view pubkeyhex)
{
    //Decode hex string and verify the signature using libsodium.

    unsigned char decoded_pubkey[PFXD_PUBKEY_BYTES];
    util::hex2bin(decoded_pubkey, PFXD_PUBKEY_BYTES, pubkeyhex);

    unsigned char decoded_sig[crypto_sign_BYTES];
    util::hex2bin(decoded_sig, crypto_sign_BYTES, sighex);

    return crypto_sign_verify_detached(
        decoded_sig,
        reinterpret_cast<const unsigned char *>(msg.data()),
        msg.length(),
        decoded_pubkey + 1); // +1 to skip prefix byte.
}

/**
 * Generate SHA 512 hash for message prepend with prefix before hashing.
 * 
 * @param msg message string.
 * @param prefix prefix char array.
 * @param char_length length of prefix char array.
 * @return SHA 512 hash.
 */
std::string sha_512_hash(const std::string &msg, const char *prefix, size_t char_length)
{
    std::string payload;
    payload.reserve(char_length + msg.size());
    payload.append(prefix);
    payload.append(msg);
    unsigned char hashchars[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hashchars, (unsigned char *)payload.data(), payload.length());
    return std::string((char *)hashchars, crypto_hash_sha512_BYTES);
}

/**
 * Generate SHA 512 hash for message prepend with prefix before hashing.
 * 
 * @param msg message string.
 * @param prefix prefix char array.
 * @param char_length length of prefix char array.
 * @return SHA 512 hash.
 */
std::string sha_512_hash(const std::string_view msg, const char *prefix, size_t char_length)
{
    std::string payload;
    payload.reserve(char_length + msg.size());
    payload.append(prefix);
    payload.append(msg.data());
    unsigned char hashchars[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hashchars, (unsigned char *)payload.data(), payload.length());
    return std::string((char *)hashchars, crypto_hash_sha512_BYTES);
}

// std::string sha_512_hash(const uint8_t *message, size_t message_size, const char* prefix, size_t char_length)
// {
//     const char *pp = reinterpret_cast<const char *>(message);

//     std::unique_ptr<char[]> buf_ptr(new char[char_length + message_size]);
//     unsigned char myBuffer[char_length + message_size];
//     unsigned char hashchars[crypto_hash_sha512_BYTES];
//     crypto_hash_sha512(hashchars, reinterpret_cast<const unsigned char *>(myBuffer), sizeof(myBuffer));
//     return std::string((char *)hashchars, crypto_hash_sha512_BYTES);
// }

} // namespace crypto