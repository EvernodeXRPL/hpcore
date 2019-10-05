#ifndef _HP_CRYPTO_H_
#define _HP_CRYPTO_H_

using namespace std;

namespace crypto
{

int init();

void generate_signing_keys(string &pubkey, string &seckey);

/**
 * Returns the signature bytes for the given message bytes using the provided secret key bytes.
 */
string sign(string &msg, string &seckey);

/**
 * Returns the base64 signature for the given message bytes using the provided base64 secret key.
 */
string sign_b64(string &msg, string &seckeyb64);

/**
 * Verifies the given signature bytes for the message bytes using the provided public key bytes.
 */
bool verify(string &msg, string &sig, string &pubkey);

/**
 * Verifies the given base64 signature with the message bytes using the provided base64 public key.
 */
bool verify_b64(string &msg, string &sigb64, string &pubkeyb64);

} // namespace crypto

#endif