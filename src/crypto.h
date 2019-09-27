#ifndef _HP_CRYPTO_H_
#define _HP_CRYPTO_H_

using namespace std;

namespace crypto
{

int init();

/**
 * Returns the length of the singature generated using crypto library.
 */
unsigned long long get_sig_len();

/**
 * Generates the signature for the given message using the contract's secret key.
 */
void sign(const unsigned char *msg, unsigned long long msg_len, unsigned char *sig);

/**
 * Returns the base64 signature for the given message using the contract's secret key.
 */
string sign_b64(string msg);

/**
 * Verifies the given signature with the message using the provided public key.
 */
bool verify(const unsigned char *msg, unsigned long long msg_len, const unsigned char *sig, const unsigned char *pubkey);

/**
 * Verifies the given base64 signature with the message using the provided base64 public key.
 */
bool verify_b64(string msg, string sigb64, string pubkeyb64);

} // namespace crypto

#endif