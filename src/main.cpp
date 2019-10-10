/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include "conf.hpp"
#include "crypto.hpp"
#include "usr/usr.hpp"

using namespace std;

int parse_cmd(int argc, char **argv);

int main(int argc, char **argv)
{
    if (parse_cmd(argc, argv) != 0)
        return -1;

    if (conf::ctx.command == "version")
    {
        cout << _HP_VERSION_ << endl;
    }
    else
    {
        if (crypto::init() != 0)
            return -1;

        if (conf::ctx.command == "new")
        {
            if (conf::create_contract() != 0)
                return -1;
        }
        else
        {
            if (conf::ctx.command == "rekey")
            {
                if (conf::rekey() != 0)
                    return -1;
            }
            else if (conf::ctx.command == "run")
            {
                if (conf::init() != 0 || usr::init() != 0)
                    return -1;
            }
        }
    }
    cout << "exited normally\n";
    return 0;
}

int parse_cmd(int argc, char **argv)
{
    if (argc > 1) //We get working dir as an arg anyway. So we need to check for >1 args.
    {
        string command = argv[1];
        conf::ctx.command = command;
        if (command == "run" || command == "new" || command == "rekey")
        {
            if (argc != 3)
            {
                cerr << "Contract directory not specified.\n";
            }
            else
            {
                conf::set_contract_dir_paths(argv[2]);

                return 0;
            }
        }
        else if (command == "version")
        {
            if (argc == 2)
                return 0;
        }
    }

    cerr << "Arguments mismatch.\n";
    cout << "Usage:\n";
    cout << "hpcore version\n";
    cout << "hpcore <command> <contract dir> (command = run | new | rekey)\n";
    cout << "Example: hpcore run ~/mycontract\n";

    return -1;
}