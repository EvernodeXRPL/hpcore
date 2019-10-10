#ifndef _HP_CRYPTO_H_
#define _HP_CRYPTO_H_

using namespace std;

/**
 * Offers convenience functions for cryptographic operations wrapping libsodium.
 * These functions are used for contract config and user/peer message authentication.
 */
namespace crypto
{

int init();

void generate_signing_keys(string &pubkey, string &seckey, string &keytype);

string sign(const string &msg, const string &seckey);

string sign_b64(const string &msg, const string &seckeyb64);

int verify(const string &msg, const string &sig, const string &pubkey);

int verify_b64(const string &msg, const string &sigb64, const string &pubkeyb64);

} // namespace crypto

#endif