#include <cstdio>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <boost/filesystem.hpp>
#include "conf.h"

using namespace std;
using namespace rapidjson;

namespace conf
{

ContractCtx ctx;
ContractConfig cfg;

void load_config()
{
    ifstream ifs(ctx.configFile);
    IStreamWrapper isw(ifs);

    Document d;
    d.ParseStream(isw);

    cfg.pubkeyb64 = d["pubkeyb64"].GetString();
    cfg.seckeyb64 = d["seckeyb64"].GetString();
    cfg.binary = d["binary"].GetString();
    cfg.binargs = d["binargs"].GetString();
    cfg.listenip = d["listenip"].GetString();

    cfg.peers.clear();
    for (auto &v : d["peers"].GetArray())
        cfg.peers.push_back(v.GetString());

    cfg.unl.clear();
    for (auto &v : d["unl"].GetArray())
        cfg.unl.push_back(v.GetString());

    cfg.peerport = d["peerport"].GetInt();
    cfg.roundtime = d["roundtime"].GetInt();
    cfg.pubport = d["pubport"].GetInt();
    cfg.pubmaxsize = d["pubmaxsize"].GetInt();
    cfg.pubmaxcpm = d["pubmaxcpm"].GetInt();
}

void save_config()
{
    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("pubkeyb64", StringRef(cfg.pubkeyb64.c_str()), allocator);
    d.AddMember("seckeyb64", StringRef(cfg.seckeyb64.c_str()), allocator);
    d.AddMember("binary", StringRef(cfg.binary.c_str()), allocator);
    d.AddMember("binargs", StringRef(cfg.binargs.c_str()), allocator);
    d.AddMember("listenip", StringRef(cfg.listenip.c_str()), allocator);

    Value peers(kArrayType);
    d.AddMember("peers", peers, allocator);
    for (int i = 0; i < cfg.peers.size(); i++)
    {
        Value v;
        v.SetString(StringRef(cfg.peers[i].c_str()), allocator);
        peers.PushBack(v, allocator);
    }

    Value unl(kArrayType);
    d.AddMember("unl", unl, allocator);
    for (int i = 0; i < cfg.unl.size(); i++)
    {
        Value v;
        v.SetString(StringRef(cfg.unl[i].c_str()), allocator);
        unl.PushBack(v, allocator);
    }

    d.AddMember("peerport", cfg.peerport, allocator);
    d.AddMember("roundtime", cfg.roundtime, allocator);
    d.AddMember("pubport", cfg.pubport, allocator);
    d.AddMember("pubmaxsize", cfg.pubmaxsize, allocator);
    d.AddMember("pubmaxcpm", cfg.pubmaxcpm, allocator);

    ofstream ofs(ctx.configFile);
    OStreamWrapper osw(ofs);

    PrettyWriter<OStreamWrapper> writer(osw);
    d.Accept(writer);
}

int parse_cmd(int argc, char **argv)
{
    if (argc == 3) //We get working dir as an arg anyway. So we need to check for 1+2 args.
    {
        string command(argv[1]);
        if (command == "run" || command == "new" || command == "rekey")
        {
            ctx.command = command;
            string dir = argv[2];
            if (dir[dir.size() - 1] == '/')
                dir = dir.substr(0, dir.size() - 1);

            ctx.contractDir = dir;
            ctx.configDir = dir + "/cfg";
            ctx.configFile = ctx.configDir + "/hp.cfg";
            ctx.histDir = dir + "/hist";
            ctx.stateDir = dir + "/state";
            ctx.binDir = dir + "/bin";
            return 1;
        }
        else
        {
            cerr << "Invalid command. 'run | new | rekey' expected.\n";
        }
    }
    else
    {
        cerr << "Argument count mismatch.\n";
    }

    cout << "Usage: hpcore <command> <contract dir> (command = run | new |rekey)\n";
    cout << "Example: hpcore run ~/mycontract\n";

    return 0;
}

int create_contract()
{
    struct stat dirInfo;

    if (boost::filesystem::exists(ctx.contractDir))
    {
        cerr << "Contract dir already exists.\n";
        return 0;
    }

    boost::filesystem::create_directories(ctx.configDir);
    boost::filesystem::create_directories(ctx.binDir);
    boost::filesystem::create_directories(ctx.histDir);
    boost::filesystem::create_directories(ctx.stateDir);

    //Create config file with default settings.
    cfg.listenip = "0.0.0.0";
    cfg.peerport = 22860;
    cfg.roundtime = 1000;
    cfg.pubport = 8080;
    cfg.pubmaxsize = 65536;
    cfg.pubmaxcpm = 100;
    save_config();
    return 1;
}

int rekey()
{
    //Clear the keys and save the config. crpyto::init will automatically init the keys.
    cfg.pubkeyb64 = "";
    cfg.seckeyb64 = "";
    save_config();
}

int init(int argc, char **argv)
{
    if (!parse_cmd(argc, argv))
        return 0;

    if (ctx.command == "new")
    {
        if (!create_contract())
            return 0;
        load_config();
    }
    else if (ctx.command == "rekey")
    {
        load_config();
        rekey();
    }
    else if (ctx.command == "run")
    {
        load_config();
        //TO DO: Contract run logic.
    }

    return 1;
}

} // namespace conf