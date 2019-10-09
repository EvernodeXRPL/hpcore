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
string sign(const string &msg, const string &seckey);

/**
 * Returns the base64 signature for the given message bytes using the provided base64 secret key.
 */
string sign_b64(const string &msg, const string &seckeyb64);

/**
 * Verifies the given signature bytes for the message bytes using the provided public key bytes.
 */
int verify(const string &msg, const string &sig, const string &pubkey);

/**
 * Verifies the given base64 signature with the message bytes using the provided base64 public key.
 */
int verify_b64(const string &msg, const string &sigb64, const string &pubkeyb64);

} // namespace crypto

#endif