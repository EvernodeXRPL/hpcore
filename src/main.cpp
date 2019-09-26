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
    if (!conf::init() || !crypto::init())
    {
        cerr << "Init error\n";
        return -1;
    }

    //Example sign and verification.
    unsigned char msg[10] = "hotpocket";
    unsigned char *sig = new unsigned char[crypto::get_sig_len()];
    crypto::sign(msg, 10, sig);

    bool isValid = crypto::verify(msg, 10, sig);

    cout << "exited normally\n";
    return 0;
}

