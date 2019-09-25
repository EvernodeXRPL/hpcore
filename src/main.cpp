/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include <sodium.h>

using namespace std;

int main(int argc, char** argv) {

    if (sodium_init() < 0) {
        cout << "sodium_init failed.\n";
        return 1;
    }

    unsigned char publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char privatekey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(publickey, privatekey);
    
    cout << "exited normally\n";
    return 0;
} 
