#include <cstdio>
#include <iostream>
#include <sodium.h>
#include "base64.h"
#include "conf.h"
#include "crypto.h"

using namespace std;
using namespace rapidjson;

namespace crypto
{
unsigned long long get_sig_len()
{
    return crypto_sign_BYTES;
}

void sign(const unsigned char *msg, unsigned long long msg_len, unsigned char *sig)
{
    crypto_sign_detached(sig, NULL, msg, msg_len, conf::cfg.seckey);
}

string sign_b64(string msg)
{
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char *)msg.c_str(), msg.size() + 1, conf::cfg.seckey);
    return base64_encode(sig, crypto_sign_BYTES);
}

bool verify(const unsigned char *msg, unsigned long long msg_len, const unsigned char *sig, const unsigned char *pubkey)
{
    int result = crypto_sign_verify_detached(sig, msg, msg_len, pubkey);
    return result == 0;
}

bool verify_b64(string msg, string sigb64, string pubkeyb64)
{
    vector<unsigned char> sigVector = base64_decode(sigb64);
    unsigned char sig[sigVector.size()];
    for (int i = 0; i < sigVector.size(); i++)
        sig[i] = sigVector[i];

    vector<unsigned char> pubkeyVector = base64_decode(pubkeyb64);
    unsigned char pubkey[pubkeyVector.size()];
    for (int i = 0; i < pubkeyVector.size(); i++)
        pubkey[i] = pubkeyVector[i];

    int result = crypto_sign_verify_detached(sig, (unsigned char *)msg.c_str(), msg.size() + 1, pubkey);
    return result == 0;
}

void cryptopair_to_b64()
{
    conf::cfg.pubkeyb64 = base64_encode(conf::cfg.pubkey, crypto_sign_PUBLICKEYBYTES);
    conf::cfg.seckeyb64 = base64_encode(conf::cfg.seckey, crypto_sign_SECRETKEYBYTES);
}

void b64pair_to_crypto()
{
    vector<unsigned char> pubDecoded = base64_decode(conf::cfg.pubkeyb64);
    vector<unsigned char> privDecoded = base64_decode(conf::cfg.seckeyb64);

    unsigned char *pubDecodedBytes = (unsigned char *)malloc(pubDecoded.size());
    unsigned char *privDecodedBytes = (unsigned char *)malloc(privDecoded.size());

    for (size_t i = 0; i < pubDecoded.size(); ++i)
        pubDecodedBytes[i] = pubDecoded[i];

    for (size_t i = 0; i < privDecoded.size(); ++i)
        privDecodedBytes[i] = privDecoded[i];

    if (conf::cfg.pubkey != NULL)
        free(conf::cfg.pubkey);

    if (conf::cfg.seckey != NULL)
        free(conf::cfg.seckey);

    conf::cfg.pubkey = pubDecodedBytes;
    conf::cfg.seckey = privDecodedBytes;
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
        cryptopair_to_b64();
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
            b64pair_to_crypto();

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

} // namespace crypto