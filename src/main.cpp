/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include <boost/thread/thread.hpp>
#include "conf.h"
#include "crypto.h"
#include "sock/server_session.h"
#include "sock/server_listener.h"
#include "sock/shared_state.h"

using namespace std;

int parse_cmd(int argc, char **argv);
void open_listen();

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

        open_listen();
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

void open_listen()
{

    auto address = net::ip::make_address(conf::cfg.listenip);
    net::io_context ioc;
    std::make_shared<server_listener>(
        ioc,
        tcp::endpoint{address, conf::cfg.peerport},
        std::make_shared<shared_state>())
        ->run();

    std::make_shared<server_listener>(
        ioc,
        tcp::endpoint{address, conf::cfg.pubport},
        std::make_shared<shared_state>())
        ->run();
    
    std::thread run_thread([&]{ ioc.run(); });
}