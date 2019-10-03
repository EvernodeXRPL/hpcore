/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include <unistd.h>
#include "conf.h"
#include "crypto.h"
#include "usr/usr.h"
#include "proc.h"

using namespace std;
using namespace shared;

int parse_cmd(int argc, char **argv);

int main(int argc, char **argv)
{
    if (!parse_cmd(argc, argv))
        return -1;

    if (conf::ctx.command == "version")
    {
        cout << _HP_VERSION_ << endl;
    }
    else
    {
        bool initSuccess = conf::init(argc, argv) && crypto::init();
        if (!initSuccess)
        {
            cerr << "Init error\n";
            return -1;
        }

        if (conf::ctx.command == "run")
        {
            //TODO
            
            usr::add_user("pku1");
            usr::add_user("pku2");
            usr::add_user("pku3");

            proc::ContractExecArgs ctargs;
            ctargs.users = &usr::users;

            proc::exec_contract(ctargs);
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
                return 1;
            }
        }
        else if (command == "version")
        {
            if (argc == 2)
                return 1;
        }
    }

    cerr << "Arguments mismatch.\n";
    cout << "Usage:\n";
    cout << "hpcore version\n";
    cout << "hpcore <command> <contract dir> (command = run | new | rekey)\n";
    cout << "Example: hpcore run ~/mycontract\n";

    return 0;
}