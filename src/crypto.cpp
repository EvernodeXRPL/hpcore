#include "pchheader.hpp"
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
        std::cout << "sodium_init failed.\n";
        return -1;
    }

    return 0;
}

/**
 * Generates a signing key pair using libsodium and assigns them to the provided strings.
 */
void generate_signing_keys(std::string &pubkey, std::string &seckey)
{
    // Generate key pair using libsodium default algorithm.
    // Currently using ed25519. So append prefix byte to represent that.

    pubkey.resize(PFXD_PUBKEY_BYTES);
    pubkey[0] = KEYPFX_ed25519;

    seckey.resize(PFXD_SECKEY_BYTES);
    seckey[0] = KEYPFX_ed25519;

    crypto_sign_ed25519_keypair(
        reinterpret_cast<unsigned char *>(pubkey.data() + 1),   // +1 to skip the prefix byte.
        reinterpret_cast<unsigned char *>(seckey.data() + 1));  // +1 to skip the prefix byte.
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
    sig.resize(crypto_sign_ed25519_BYTES);
    crypto_sign_ed25519_detached(
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

    unsigned char sig[crypto_sign_ed25519_BYTES];
    crypto_sign_ed25519_detached(
        sig,
        NULL,
        reinterpret_cast<const unsigned char *>(msg.data()),
        msg.length(),
        seckey + 1); // +1 to skip prefix byte.

    std::string sighex;
    util::bin2hex(sighex, sig, crypto_sign_ed25519_BYTES);
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
    return crypto_sign_ed25519_verify_detached(
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

    unsigned char decoded_sig[crypto_sign_ed25519_BYTES];
    util::hex2bin(decoded_sig, crypto_sign_ed25519_BYTES, sighex);

    return crypto_sign_ed25519_verify_detached(
        decoded_sig,
        reinterpret_cast<const unsigned char *>(msg.data()),
        msg.length(),
        decoded_pubkey + 1); // +1 to skip prefix byte.
}

/**
 * Generate blake2b hash for a given message.
 * @param data String to hash.
 * @return The blake2b hash of the given string.
 */
std::string get_hash(std::string_view data)
{
    std::string hash;
    hash.resize(crypto_generichash_blake2b_BYTES);

    crypto_generichash_blake2b(
        reinterpret_cast<unsigned char *>(hash.data()),
        hash.length(),
        reinterpret_cast<const unsigned char *>(data.data()),
        data.length(),
        NULL, 0);

    return hash;
}

/**
 * Generate blake2b hash for a given message.
 * @param data unsigned char array pointer to hash data.
 * @param data_length hash data length.
 * @return The blake2b hash of the pointed buffer.
 */
std::string get_hash(const unsigned char * data, size_t data_length)
{
    std::string hash;
    hash.resize(crypto_generichash_blake2b_BYTES);

    crypto_generichash_blake2b(
        reinterpret_cast<unsigned char *>(hash.data()),
        hash.length(),
        data,
        data_length,
        NULL, 0);

    return hash;
}

/**
 * Generates blake2b hash for the given set of strings using stream hashing.
 */
std::string get_hash(std::string_view s1, std::string_view s2)
{
    std::string hash;
    hash.resize(crypto_generichash_blake2b_BYTES);

    // Init stream hashing.
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, NULL, 0, hash.length());

    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(s1.data()), s1.length());
    crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(s2.data()), s2.length());

    // Get the final hash.
    crypto_generichash_blake2b_final(
        &state,
        reinterpret_cast<unsigned char *>(hash.data()),
        hash.length());

    return hash;
}

} // namespace crypto