#include <cstdio>
#include <iostream>
#include <sodium.h>
#include "crypto.h"
#include "util.h"

using namespace std;

namespace crypto
{

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
    //Generate key pair using libsodium default algorithm. (Currently using ed25519)

    unsigned char pubkeychars[crypto_sign_PUBLICKEYBYTES];
    unsigned char seckeychars[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pubkeychars, seckeychars);

    util::replace_string_contents(pubkey, (char *)pubkeychars, crypto_sign_PUBLICKEYBYTES);
    util::replace_string_contents(seckey, (char *)seckeychars, crypto_sign_SECRETKEYBYTES);
}

string sign(const string &msg, const string &seckey)
{
    //Generate the signature using libsodium.

    unsigned char sigchars[crypto_sign_BYTES];
    crypto_sign_detached(sigchars, NULL, (unsigned char *)msg.data(), msg.length(), (unsigned char *)seckey.data());
    string sig((char *)sigchars, crypto_sign_BYTES);
    return sig;
}

string sign_b64(const string &msg, const string &seckeyb64)
{
    //Decode b64 string and generate the signature using libsodium.

    unsigned char seckey[crypto_sign_SECRETKEYBYTES];
    util::base64_decode(seckeyb64, seckey, crypto_sign_SECRETKEYBYTES);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char *)msg.data(), msg.length(), seckey);

    string sigb64;
    util::base64_encode(sig, crypto_sign_BYTES, sigb64);
    return sigb64;
}

int verify(const string &msg, const string &sig, const string &pubkey)
{
    return crypto_sign_verify_detached(
        (unsigned char *)sig.data(), (unsigned char *)msg.data(), msg.length(), (unsigned char *)pubkey.data());
}

int verify_b64(const string &msg, const string &sigb64, const string &pubkeyb64)
{
    //Decode b64 string and verify the signature using libsodium.

    unsigned char decoded_pubkey[crypto_sign_PUBLICKEYBYTES];
    util::base64_decode(pubkeyb64, decoded_pubkey, crypto_sign_PUBLICKEYBYTES);

    unsigned char decoded_sig[crypto_sign_BYTES];
    util::base64_decode(sigb64, decoded_sig, crypto_sign_BYTES);

    return crypto_sign_verify_detached(decoded_sig, (unsigned char *)msg.data(), msg.length(), decoded_pubkey);
}

} // namespace crypto