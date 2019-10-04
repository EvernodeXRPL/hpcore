#include <cstdio>
#include <iostream>
#include <sodium.h>
#include "conf.h"
#include "crypto.h"
#include "shared.h"

using namespace std;
using namespace rapidjson;

namespace crypto
{

void generate_crypto_keys();
void binpair_to_b64();
int b64pair_to_bin();

void sign(const unsigned char *msg, unsigned long long msg_len, unsigned char *sig)
{
    crypto_sign_detached(sig, NULL, msg, msg_len, conf::cfg.seckey);
}

string sign_b64(string &msg)
{
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char *)msg.data(), msg.size() + 1, conf::cfg.seckey);
    return shared::base64_encode(sig, crypto_sign_BYTES);
}

bool verify(const unsigned char *msg, unsigned long long msg_len, const unsigned char *sig, const unsigned char *pubkey)
{
    int result = crypto_sign_verify_detached(sig, msg, msg_len, pubkey);
    return result == 0;
}

bool verify_b64(string &msg, string &sigb64, string &pubkeyb64)
{
    unsigned char decoded_pubkey[crypto_sign_PUBLICKEYBYTES];
    shared::base64_decode(pubkeyb64, decoded_pubkey, crypto_sign_PUBLICKEYBYTES);

    unsigned char decoded_sig[crypto_sign_BYTES];
    shared::base64_decode(sigb64, decoded_sig, crypto_sign_BYTES);

    int result = crypto_sign_verify_detached(decoded_sig, (unsigned char *)msg.data(), msg.size() + 1, decoded_pubkey);
    return result == 0;
}

int init()
{
    if (sodium_init() < 0)
    {
        cerr << "sodium_init failed.\n";
        return 0;
    }

    if (conf::ctx.command == "new" || conf::ctx.command == "rekey")
    {
        cout << "Generating new keys.\n";
        generate_crypto_keys();
        binpair_to_b64();

        conf::save_config();
    }
    else if (conf::ctx.command == "run")
    {
        if (conf::cfg.pubkeyb64.empty() || conf::cfg.seckeyb64.empty())
        {
            cerr << "Signing keys missing. Run with 'rekey' to generate new keys.\n";
            return 0;
        }
        else
        {
            //Decode b64 keys into bytes and store in memory.
            if (!b64pair_to_bin())
                return 0;

            //Sign and verify a sample to ensure we have a matching key pair.
            string msg = "hotpocket";
            string sigb64 = sign_b64(msg);
            if (!verify_b64(msg, sigb64, conf::cfg.pubkeyb64))
            {
                cerr << "Invalid signing keys. Run with 'rekey' to generate new keys.\n";
                return 0;
            }
        }
    }

    return 1;
}

void generate_crypto_keys()
{
    if (conf::cfg.pubkey != NULL)
        free(conf::cfg.pubkey);

    if (conf::cfg.seckey != NULL)
        free(conf::cfg.seckey);

    conf::cfg.pubkey = (unsigned char *)malloc(crypto_sign_PUBLICKEYBYTES);
    conf::cfg.seckey = (unsigned char *)malloc(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(conf::cfg.pubkey, conf::cfg.seckey);
}

void binpair_to_b64()
{
    conf::cfg.pubkeyb64 = shared::base64_encode(conf::cfg.pubkey, crypto_sign_PUBLICKEYBYTES);
    conf::cfg.seckeyb64 = shared::base64_encode(conf::cfg.seckey, crypto_sign_SECRETKEYBYTES);
}

int b64pair_to_bin()
{
    unsigned char *decoded_pubkey = (unsigned char *)malloc(crypto_sign_PUBLICKEYBYTES);
    unsigned char *decoded_seckey = (unsigned char *)malloc(crypto_sign_SECRETKEYBYTES);

    if (!shared::base64_decode(conf::cfg.pubkeyb64, decoded_pubkey, crypto_sign_PUBLICKEYBYTES))
    {
        cerr << "Error decoding public key.\n";
        return 0;
    }

    if (!shared::base64_decode(conf::cfg.seckeyb64, decoded_seckey, crypto_sign_SECRETKEYBYTES))
    {
        cerr << "Error decoding secret key.\n";
        return 0;
    }

    if (conf::cfg.pubkey != NULL)
        free(conf::cfg.pubkey);

    if (conf::cfg.seckey != NULL)
        free(conf::cfg.seckey);

    conf::cfg.pubkey = decoded_pubkey;
    conf::cfg.seckey = decoded_seckey;
    return 1;
}

} // namespace crypto