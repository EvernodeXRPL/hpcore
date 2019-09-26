/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include "conf.h"
#include "keys.h"

using namespace std;

int main(int argc, char **argv)
{
    if (!conf::init() || !keys::init())
    {
        cerr << "Init error\n";
        return -1;
    }

    cout << "exited normally\n";
    return 0;
}

