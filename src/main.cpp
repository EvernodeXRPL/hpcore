/**
    Entry point for HP Core
**/

#include <cstdio>
#include <iostream>
#include <boost/thread/thread.hpp>
#include "conf.h"
#include "crypto.h"
#include "usr/usr.h"
#include "sock/socket_server.h"
#include "sock/socket_client.h"
#include "sock/socket_session_handler.h"
#include "peer_session_handler.h"
#include "public_session_handler.h"

using namespace std;

peer_session_handler peer_session_manager;
public_session_handler public_session_manager;

int parse_cmd(int argc, char **argv);
void open_listen();

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

    return 0;
}

void open_listen()
{

    auto address = net::ip::make_address(conf::cfg.listenip);
    net::io_context ioc;

    // std::make_shared<sock::socket_server>(
    //     ioc,
    //     tcp::endpoint{address, conf::cfg.peerport},
    //     peer_session_manager)
    //     ->run();

    // std::make_shared<sock::socket_server>(
    //     ioc,
    //     tcp::endpoint{address, conf::cfg.pubport},
    //     public_session_manager)
    //     ->run();

    std::make_shared<sock::socket_client>(ioc, peer_session_manager)->run((conf::cfg.listenip).c_str(), "23000");

    std::thread run_thread([&] { ioc.run(); });
    int t;
    std::cin >> t;
}