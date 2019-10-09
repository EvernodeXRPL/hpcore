#include <cstdio>
#include <iostream>
#include <sodium.h>
#include "crypto.h"
#include "shared.h"

using namespace std;

namespace crypto
{

void generate_signing_keys();
void binpair_to_b64();
int b64pair_to_bin();

string sign(string &msg, string &seckey)
{
    unsigned char sigchars[crypto_sign_BYTES];
    crypto_sign_detached(sigchars, NULL, (unsigned char *)msg.data(), msg.length(), (unsigned char *)seckey.data());
    string sig((char *)sigchars, crypto_sign_BYTES);
    return sig;
}

string sign_b64(string &msg, string &seckeyb64)
{
    unsigned char seckey[crypto_sign_SECRETKEYBYTES];
    shared::base64_decode(seckeyb64, seckey, crypto_sign_SECRETKEYBYTES);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char *)msg.data(), msg.length(), seckey);
    string sigb64;
    shared::base64_encode(sig, crypto_sign_BYTES, sigb64);
    return sigb64;
}

bool verify(string &msg, string &sig, string &pubkey)
{
    int result = crypto_sign_verify_detached(
        (unsigned char *)sig.data(), (unsigned char *)msg.data(), msg.length(), (unsigned char *)pubkey.data());
    return result == 0;
}

bool verify_b64(string &msg, string &sigb64, string &pubkeyb64)
{
    unsigned char decoded_pubkey[crypto_sign_PUBLICKEYBYTES];
    shared::base64_decode(pubkeyb64, decoded_pubkey, crypto_sign_PUBLICKEYBYTES);

    unsigned char decoded_sig[crypto_sign_BYTES];
    shared::base64_decode(sigb64, decoded_sig, crypto_sign_BYTES);

    int result = crypto_sign_verify_detached(decoded_sig, (unsigned char *)msg.data(), msg.length(), decoded_pubkey);
    return result == 0;
}

int init()
{
    if (sodium_init() < 0)
    {
        cerr << "sodium_init failed.\n";
        return -1;
    }

    return 0;
}

void generate_signing_keys(string &pubkey, string &seckey)
{
    unsigned char pubkeychars[crypto_sign_PUBLICKEYBYTES];
    unsigned char seckeychars[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pubkeychars, seckeychars);

    shared::replace_string_contents(pubkey, (char *)pubkeychars, crypto_sign_PUBLICKEYBYTES);
    shared::replace_string_contents(seckey, (char *)seckeychars, crypto_sign_SECRETKEYBYTES);
}

} // namespace crypto