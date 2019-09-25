#include <cstdio>
#include <iostream>
#include <sodium.h>
#include <fstream>
#include <libconfig.h++>
#include "base64.h"

using namespace std;
using namespace libconfig;

static const char CFG_FILE[] = "keys.cfg";
static const char KEY_PUBLIC[] = "public";
static const char KEY_PRIVATE[] = "private";

int init_keys()
{
    bool keysInitialized = false;

    Config cfg;

    try
    {
        //Attempt to read keys from the config file.
        cfg.readFile(CFG_FILE);

        string filePublicKey = cfg.lookup(KEY_PUBLIC);
        string filePrivateKey = cfg.lookup(KEY_PRIVATE);

        //TODO: Make the keys available via a global variable or helper func.

        keysInitialized = true;
    }
    catch (const SettingNotFoundException &nfex)
    {
        cerr << "Keys not found in configuration file." << endl;
    }
    catch (const FileIOException &fioex)
    {
        cerr << "Keys file not found." << endl;
    }

    //If for some reason we couldn't load the keys, we regenerate the keys.
    if (!keysInitialized)
    {
        cout << "Generating keys" << endl;

        //Initialize new keys
        unsigned char publickey[crypto_box_PUBLICKEYBYTES];
        unsigned char privatekey[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(publickey, privatekey);

        //Create the file if not exists.
        ofstream file{CFG_FILE};

        //Write the keys into the file.
        cfg.readFile(CFG_FILE);
        Setting &root = cfg.getRoot();
        root.add(KEY_PUBLIC, Setting::TypeString) = base64_encode(publickey, crypto_box_PUBLICKEYBYTES);
        root.add(KEY_PRIVATE, Setting::TypeString) = base64_encode(privatekey, crypto_box_SECRETKEYBYTES);
        cfg.writeFile(CFG_FILE);
    }
}
