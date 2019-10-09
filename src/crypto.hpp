#ifndef _HP_CRYPTO_H_
#define _HP_CRYPTO_H_

using namespace std;

namespace crypto
{

/**
 * Initializes the crypto subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
int init();

/**
 * Generates a signing key pair using libsodium and assigns them to the provided strings.
 */
void generate_signing_keys(string &pubkey, string &seckey);

/**
 * Returns the signature bytes for a message.
 * 
 * @param msg Message bytes to sign.
 * @param seckey Secret key bytes.
 * @return Signature bytes.
 */
string sign(const string &msg, const string &seckey);

/**
 * Returns the base64 signature string for a message.
 * 
 * @param msg Base64 message string to sign.
 * @param seckey Base64 secret key string.
 * @return Base64 signature string.
 */
string sign_b64(const string &msg, const string &seckeyb64);

/**
 * Verifies the given signature bytes for the message.
 * 
 * @param msg Message bytes.
 * @param sig Signature bytes.
 * @param pubkey Public key bytes.
 * @return 0 for successful verification. -1 for failure.
 */
int verify(const string &msg, const string &sig, const string &pubkey);

/**
 * Verifies the given base64 signature for the message.
 * 
 * @param msg Base64 message string.
 * @param sig Base64 signature string.
 * @param pubkey Base64 secret key.
 * @return 0 for successful verification. -1 for failure.
 */
int verify_b64(const string &msg, const string &sigb64, const string &pubkeyb64);

} // namespace crypto

#endif