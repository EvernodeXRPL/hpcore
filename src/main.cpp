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
    string msg = "hotpocket";
    string sigb64 = crypto::sign_b64(msg);
    cout << "Message: " << msg << endl;
    cout << "Signature: " << sigb64 << endl;

    bool isValid = crypto::verify_b64(msg, sigb64, conf::cfg.pubkeyb64);
    if (isValid)
        cout << "Signature verified.\n";
    else
        cout << "Invalid signature.\n";

    cout << "exited normally\n";
    return 0;
}
