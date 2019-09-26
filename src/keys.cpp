#include <cstdio>
#include <iostream>
#include <sodium.h>
#include <fstream>
#include <libconfig.h++>
#include "base64.h"
#include "lib/rapidjson/document.h"
#include "conf.h"

using namespace std;
using namespace libconfig;
using namespace rapidjson;

namespace keys
{

static const char CFG_FILE[] = "keys.cfg";
static const char KEY_PUBLIC[] = "public";
static const char KEY_PRIVATE[] = "private";

//Struct used for storing in JSON
struct KeyPairB64
{
    const char *publicKey;
    const char *privateKey;
};

//Struct used for crypto operations
struct KeyPairCrypto
{
    BYTE *publicKey;
    BYTE *privateKey;
};

static KeyPairB64 b64KeyPair;
static KeyPairCrypto cryptoKeyPair;

void load_keys_b64()
{
    Document d;
    conf::load(CFG_FILE, d);
    if (!d.IsNull())
    {
        b64KeyPair.publicKey = d["public"].GetString();
        b64KeyPair.privateKey = d["private"].GetString();
    }
    else
    {
        b64KeyPair.publicKey = NULL;
        b64KeyPair.privateKey = NULL;
    }
}

void save_keys_b64()
{
    Document d;
    d.SetObject();

    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("public", StringRef(b64KeyPair.publicKey), allocator);
    d.AddMember("private", StringRef(b64KeyPair.privateKey), allocator);
    conf::save(CFG_FILE, d);
}

void cryptopair_to_b64()
{
    string b64PubKey = base64_encode(cryptoKeyPair.publicKey, crypto_sign_PUBLICKEYBYTES);
    string b64PrivKey = base64_encode(cryptoKeyPair.publicKey, crypto_sign_SECRETKEYBYTES);

    char *b64PubKeyChar = (char *)malloc(b64PubKey.size() + 1);
    char *b64PrivKeyChar = (char *)malloc(b64PrivKey.size() + 1);

    strcpy(b64PubKeyChar, &b64PubKey[0]);
    strcpy(b64PrivKeyChar, &b64PrivKey[0]);

    b64KeyPair.publicKey = b64PubKeyChar;
    b64KeyPair.privateKey = b64PrivKeyChar;
}

void b64pair_to_crypto()
{
    vector<BYTE> pubDecoded = base64_decode(b64KeyPair.publicKey);
    vector<BYTE> privDecoded = base64_decode(b64KeyPair.privateKey);

    BYTE *pubDecodedBytes = (BYTE *)malloc(pubDecoded.size());
    BYTE *privDecodedBytes = (BYTE *)malloc(privDecoded.size());

    for (size_t i = 0; i < pubDecoded.size(); ++i)
    {
        pubDecodedBytes[i] = pubDecoded[i];
    }
    for (size_t i = 0; i < privDecoded.size(); ++i)
    {
        privDecodedBytes[i] = privDecoded[i];
    }

    cryptoKeyPair.publicKey = pubDecodedBytes;
    cryptoKeyPair.privateKey = privDecodedBytes;
}

void generate_crypto_keys()
{
    BYTE *pubKey = (BYTE *)malloc(crypto_sign_PUBLICKEYBYTES);
    BYTE *privKey = (BYTE *)malloc(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pubKey, privKey);

    cryptoKeyPair.publicKey = pubKey;
    cryptoKeyPair.privateKey = privKey;
}

int init()
{
    if (sodium_init() < 0)
    {
        cerr << "sodium_init failed.\n";
        return 0;
    }

    load_keys_b64();

    //If any keys are missing generate a new pair and save to file.
    if (!b64KeyPair.publicKey || !b64KeyPair.privateKey)
    {
        cout << "Keys not found. Generating.\n";
        generate_crypto_keys();
        cryptopair_to_b64();
        save_keys_b64();
    }
    else
    {
        b64pair_to_crypto();
        cout << "Keys loaded from file.\n";
    }

    return 1;
}

} // namespace keys