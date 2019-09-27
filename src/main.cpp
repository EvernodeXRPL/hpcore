/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include "conf.h"
#include "crypto.h"

using namespace std;

int main(int argc, char **argv)
{
    if (!(conf::init(argc, argv) && crypto::init()))
    {
        cerr << "Init error\n";
        return -1;
    }

    //Example sign and verification.
    unsigned char msg[10] = "hotpocket";
    unsigned char *sig = new unsigned char[crypto::get_sig_len()];
    crypto::sign(msg, 10, sig, conf::cfg.seckey);

    bool isValid = crypto::verify(msg, 10, sig, conf::cfg.pubkey);
    if (isValid)
        cout << "Signature verified.\n";
    else
        cout << "Invalid signature.\n";

    cout << "exited normally\n";
    return 0;
}
