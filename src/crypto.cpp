#include <cstdio>
#include <iostream>
#include <sodium.h>
#include "crypto.hpp"
#include "util.hpp"

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
    //Generate key pair using libsodium default algorithm. (Currently using ed25519)

    unsigned char pubkeychars[crypto_sign_PUBLICKEYBYTES];
    unsigned char seckeychars[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pubkeychars, seckeychars);

    pubkey = std::string((char *)pubkeychars, crypto_sign_PUBLICKEYBYTES);
    seckey = std::string((char *)seckeychars, crypto_sign_SECRETKEYBYTES);
    keytype = crypto_sign_primitive();
}

/**
 * Returns the signature bytes for a message.
 * 
 * @param msg Message bytes to sign.
 * @param seckey Secret key bytes.
 * @return Signature bytes.
 */
std::string sign(const std::string &msg, const std::string &seckey)
{
    //Generate the signature using libsodium.

    unsigned char sigchars[crypto_sign_BYTES];
    crypto_sign_detached(sigchars, NULL, (unsigned char *)msg.data(), msg.length(), (unsigned char *)seckey.data());
    std::string sig((char *)sigchars, crypto_sign_BYTES);
    return sig;
}

/**
 * Returns the base64 signature string for a message.
 * 
 * @param msg Message bytes to sign.
 * @param seckeyb64 Base64 secret key string.
 * @return Base64 signature string.
 */
std::string sign_b64(const std::string &msg, const std::string &seckeyb64)
{
    //Decode b64 string and generate the signature using libsodium.

    unsigned char seckey[crypto_sign_SECRETKEYBYTES];
    util::base64_decode(seckey, crypto_sign_SECRETKEYBYTES, seckeyb64);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char *)msg.data(), msg.length(), seckey);

    std::string sigb64;
    util::base64_encode(sigb64, sig, crypto_sign_BYTES);
    return sigb64;
}

/**
 * Verifies the given signature bytes for the message.
 * 
 * @param msg Message bytes.
 * @param sig Signature bytes.
 * @param pubkey Public key bytes.
 * @return 0 for successful verification. -1 for failure.
 */
int verify(const std::string &msg, const std::string &sig, const std::string &pubkey)
{
    return crypto_sign_verify_detached(
        (unsigned char *)sig.data(), (unsigned char *)msg.data(), msg.length(), (unsigned char *)pubkey.data());
}

/**
 * Verifies the given base64 signature for the message.
 * 
 * @param msg Base64 message string.
 * @param sigb64 Base64 signature string.
 * @param pubkeyb64 Base64 secret key.
 * @return 0 for successful verification. -1 for failure.
 */
int verify_b64(const std::string &msg, const std::string &sigb64, const std::string &pubkeyb64)
{
    //Decode b64 string and verify the signature using libsodium.

    unsigned char decoded_pubkey[crypto_sign_PUBLICKEYBYTES];
    util::base64_decode(decoded_pubkey, crypto_sign_PUBLICKEYBYTES, pubkeyb64);

    unsigned char decoded_sig[crypto_sign_BYTES];
    util::base64_decode(decoded_sig, crypto_sign_BYTES, sigb64);

    return crypto_sign_verify_detached(decoded_sig, (unsigned char *)msg.data(), msg.length(), decoded_pubkey);
}

} // namespace crypto