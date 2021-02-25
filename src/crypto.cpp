#include "pchheader.hpp"
#include "crypto.hpp"
#include "util/util.hpp"

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
    void generate_signing_keys(std::string &pubkey, std::string &seckey)
    {
        // Generate key pair using libsodium default algorithm.
        // Currently using ed25519. So append prefix byte to represent that.

        pubkey.resize(crypto_sign_ed25519_PUBLICKEYBYTES + 1);
        pubkey[0] = KEYPFX_ed25519;

        seckey.resize(crypto_sign_ed25519_SECRETKEYBYTES + 1);
        seckey[0] = KEYPFX_ed25519;

        crypto_sign_ed25519_keypair(
            reinterpret_cast<unsigned char *>(pubkey.data() + 1),  // +1 to skip the prefix byte.
            reinterpret_cast<unsigned char *>(seckey.data() + 1)); // +1 to skip the prefix byte.
    }

    /**
     * Returns the signature bytes for a message.
     * 
     * @param msg Message bytes to sign.
     * @param private_key Private key bytes.
     * @return Signature bytes.
     */
    const std::string sign(std::string_view msg, std::string_view private_key)
    {
        //Generate the signature using libsodium.

        std::string sig;
        sig.resize(crypto_sign_ed25519_BYTES);
        crypto_sign_ed25519_detached(
            reinterpret_cast<unsigned char *>(sig.data()),
            NULL,
            reinterpret_cast<const unsigned char *>(msg.data()),
            msg.length(),
            reinterpret_cast<const unsigned char *>(private_key.data() + 1)); // +1 to skip the prefix byte.

        return sig;
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
     * Generate random bytes of specified length.
     */
    void random_bytes(std::string &result, const size_t len)
    {
        result.resize(len);
        randombytes_buf(result.data(), len);
    }

    /**
     * Generate blake3 hash for a given message.
     * @param data String to hash.
     * @return The blake3 hash of the given string.
     */
    const std::string get_hash(std::string_view data)
    {
        std::string hash;
        hash.resize(BLAKE3_OUT_LEN);

        // Initialize the hasher.
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        blake3_hasher_update(&hasher, reinterpret_cast<const unsigned char *>(data.data()), data.length());

        blake3_hasher_finalize(&hasher, reinterpret_cast<unsigned char *>(hash.data()), hash.length());

        return hash;
    }

    /**
     * Generate blake3 hash for a given message.
     * @param data unsigned char array pointer to hash data.
     * @param data_length hash data length.
     * @return The blake3 hash of the pointed buffer.
     */
    const std::string get_hash(const void *data, const size_t data_length)
    {
        std::string hash;
        hash.resize(BLAKE3_OUT_LEN);

        // Initialize the hasher.
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        blake3_hasher_update(&hasher, data, data_length);

        blake3_hasher_finalize(&hasher, reinterpret_cast<unsigned char *>(hash.data()), hash.length());

        return hash;
    }

    /**
     * Generates blake3 hash for the given set of strings using stream hashing.
     */
    const std::string get_hash(std::string_view s1, std::string_view s2)
    {
        std::string hash;
        hash.resize(BLAKE3_OUT_LEN);

        // Init stream hashing.
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        // updating hash with given data
        blake3_hasher_update(&hasher, reinterpret_cast<const unsigned char *>(s1.data()), s1.length());
        blake3_hasher_update(&hasher, reinterpret_cast<const unsigned char *>(s2.data()), s2.length());

        // Get the final hash.
        blake3_hasher_finalize(&hasher, reinterpret_cast<unsigned char *>(hash.data()), hash.length());

        return hash;
    }

    /**
     * Generates blake3 hash for the given string view vector using stream hashing.
     */
    const std::string get_hash(const std::vector<std::string_view> &sw_vect)
    {
        std::string hash;
        hash.resize(BLAKE3_OUT_LEN);

        if (sw_vect.empty())
        {
            return hash;
        }

        // Init stream hashing.
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        // Hash is generated only using message in contract output struct.
        for (std::string_view sw : sw_vect)
            blake3_hasher_update(&hasher, reinterpret_cast<const unsigned char *>(sw.data()), sw.length());

        // Get the final hash.
        blake3_hasher_finalize(&hasher, reinterpret_cast<unsigned char *>(hash.data()), hash.length());

        return hash;
    }

    /**
     * Generates blake3 hash for the given string set using stream hashing.
     */
    const std::string get_hash(const std::set<std::string> &sw_set)
    {
        std::string hash;
        hash.resize(BLAKE3_OUT_LEN);

        if (sw_set.empty())
        {
            return hash;
        }

        // Init stream hashing.
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        // Hash is generated only using message in contract output struct.
        for (std::string_view sw : sw_set)
            blake3_hasher_update(&hasher, reinterpret_cast<const unsigned char *>(sw.data()), sw.length());

        // Get the final hash.
        blake3_hasher_finalize(&hasher, reinterpret_cast<unsigned char *>(hash.data()), hash.length());

        return hash;
    }

    const std::string generate_uuid()
    {
        std::string rand_bytes;
        random_bytes(rand_bytes, 16);

        // Set bits for UUID v4 variant 1.
        uint8_t *uuid = (uint8_t *)rand_bytes.data();
        uuid[6] = (uuid[8] & 0x0F) | 0x40;
        uuid[8] = (uuid[8] & 0xBF) | 0x80;

        const std::string hex = util::to_hex(rand_bytes);
        return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" + hex.substr(20);
    }

} // namespace crypto