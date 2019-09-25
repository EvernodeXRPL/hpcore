/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include <sodium.h>
#include "keys.h"

using namespace std;

int main(int argc, char **argv)
{
    if (sodium_init() < 0)
    {
        cout << "sodium_init failed.\n";
        return 1;
    }

    init_keys();

    cout << "exited normally\n";
    return 0;
}
