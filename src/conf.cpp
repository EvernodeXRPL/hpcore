#include <cstdio>
#include <iostream>
#include <fstream>
#include <rapidjson/document.h>
#include <rapidjson/schema.h>
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

const char *cfg_schema =
    "{"
    "\"type\": \"object\","
    "\"required\": [ \"version\", \"pubkeyb64\", \"seckeyb64\", \"binary\", \"binargs\", \"listenip\""
    ", \"peers\", \"unl\", \"peerport\", \"roundtime\", \"pubport\", \"pubmaxsize\", \"pubmaxcpm\" ],"
    "\"properties\": {"
    "\"version\": { \"type\": \"string\" },"
    "\"pubkeyb64\": { \"type\": \"string\" },"
    "\"seckeyb64\": { \"type\": \"string\" },"
    "\"binary\": { \"type\": \"string\" },"
    "\"binargs\": { \"type\": \"string\" },"
    "\"listenip\": { \"type\": \"string\" },"
    "\"peers\": {"
    "\"type\": \"array\","
    "\"items\": { \"type\": \"string\" }"
    "},"
    "\"unl\": {"
    "\"type\": \"array\","
    "\"items\": { \"type\": \"string\" }"
    "},"
    "\"peerport\": { \"type\": \"integer\" },"
    "\"roundtime\": { \"type\": \"integer\" },"
    "\"pubport\": { \"type\": \"integer\" },"
    "\"pubmaxsize\": { \"type\": \"integer\" },"
    "\"pubmaxcpm\": { \"type\": \"integer\" }"
    "}"
    "}";

//   v1 <  v2  -> -1
//   v1 == v2  ->  0
//   v1 >  v2  -> +1
int version_compare(std::string v1, std::string v2)
{
    size_t i = 0, j = 0;
    while (i < v1.length() || j < v2.length())
    {
        int acc1 = 0, acc2 = 0;

        while (i < v1.length() && v1[i] != '.')
        {
            acc1 = acc1 * 10 + (v1[i] - '0');
            i++;
        }
        while (j < v2.length() && v2[j] != '.')
        {
            acc2 = acc2 * 10 + (v2[j] - '0');
            j++;
        }

        if (acc1 < acc2)
            return -1;
        if (acc1 > acc2)
            return +1;

        ++i;
        ++j;
    }
    return 0;
}

bool is_schema_valid(Document &d)
{
    Document sd;
    sd.Parse(cfg_schema);
    SchemaDocument schema(sd);

    SchemaValidator validator(schema);
    return d.Accept(validator);
}

int load_config()
{
    ifstream ifs(ctx.configFile);
    IStreamWrapper isw(ifs);

    Document d;
    if (d.ParseStream(isw).HasParseError())
    {
        cerr << "Invalid config file format. Parser error at position " << d.GetErrorOffset() << endl;
        return 0;
    }
    else if (!is_schema_valid(d))
    {
        cerr << "Invalid config file format.\n";
        return 0;
    }

    //Check contract version.
    string cfgVersion = d["version"].GetString();
    if (version_compare(cfgVersion, _HP_MIN_CONTRACT_VERSION_) == -1)
    {
        cerr << "Contract version too old. Minimum "
             << _HP_MIN_CONTRACT_VERSION_ << " required. "
             << cfgVersion << " found.\n";
        return 0;
    }

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

    return 1;
}

void save_config()
{
    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", StringRef(_HP_VERSION_), allocator);
    d.AddMember("pubkeyb64", StringRef(cfg.pubkeyb64.data()), allocator);
    d.AddMember("seckeyb64", StringRef(cfg.seckeyb64.data()), allocator);
    d.AddMember("binary", StringRef(cfg.binary.data()), allocator);
    d.AddMember("binargs", StringRef(cfg.binargs.data()), allocator);
    d.AddMember("listenip", StringRef(cfg.listenip.data()), allocator);

    Value peers(kArrayType);
    d.AddMember("peers", peers, allocator);
    for (int i = 0; i < cfg.peers.size(); i++)
    {
        Value v;
        v.SetString(StringRef(cfg.peers[i].data()), allocator);
        peers.PushBack(v, allocator);
    }

    Value unl(kArrayType);
    d.AddMember("unl", unl, allocator);
    for (int i = 0; i < cfg.unl.size(); i++)
    {
        Value v;
        v.SetString(StringRef(cfg.unl[i].data()), allocator);
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

void set_contract_dir_paths(string basedir)
{
    if (basedir[basedir.size() - 1] == '/')
        basedir = basedir.substr(0, basedir.size() - 1);

    ctx.contractDir = basedir;
    ctx.configDir = basedir + "/cfg";
    ctx.configFile = ctx.configDir + "/hp.cfg";
    ctx.histDir = basedir + "/hist";
    ctx.stateDir = basedir + "/state";
    ctx.binDir = basedir + "/bin";
}

int create_contract()
{
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

int clear_keys()
{
    cfg.pubkeyb64 = "";
    cfg.seckeyb64 = "";
    save_config();
}

int init(int argc, char **argv)
{
    if (ctx.command == "new")
    {
        if (!create_contract())
            return 0;
    }

    if (!load_config())
        return 0;

    if (ctx.command == "rekey")
    {
        //Clear the keys. crpyto::init will automatically init the keys.
        clear_keys();
    }
    else if (ctx.command == "run")
    {
        //TO DO: Contract run logic.
    }

    return 1;
}

} // namespace conf