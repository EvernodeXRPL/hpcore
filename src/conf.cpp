#include <cstdio>
#include <iostream>
#include <fstream>
#include <sodium.h>
#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <boost/filesystem.hpp>
#include "conf.h"
#include "crypto.h"
#include "shared.h"

using namespace std;
using namespace rapidjson;

namespace conf
{

ContractCtx ctx;
ContractConfig cfg;

bool validate_config();
int load_config();
void save_config();
void binpair_to_b64();
int b64pair_to_bin();
bool validate_contract_dir_paths();
bool is_schema_valid(Document &d);

int init()
{
    if (!validate_contract_dir_paths() || load_config() != 0 || !validate_config())
        return -1;

    return 0;
}

int rekey()
{
    if (load_config() != 0)
        return -1;

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey);
    binpair_to_b64();

    save_config();

    cout << "New signing keys generated at " << ctx.configFile << endl;

    return 0;
}

int load_config()
{
    ifstream ifs(ctx.configFile);
    IStreamWrapper isw(ifs);

    Document d;
    if (d.ParseStream(isw).HasParseError())
    {
        cerr << "Invalid config file format. Parser error at position " << d.GetErrorOffset() << endl;
        return -1;
    }
    else if (!is_schema_valid(d))
    {
        cerr << "Invalid config file format.\n";
        return -1;
    }

    //Check contract version.
    string cfgversion = d["version"].GetString();
    if (cfgversion.empty())
    {
        cerr << "Contract config version missing.\n";
        return -1;
    }

    string minversion = string(_HP_MIN_CONTRACT_VERSION_);
    if (shared::version_compare(cfgversion, minversion) == -1)
    {
        cerr << "Contract version too old. Minimum "
             << _HP_MIN_CONTRACT_VERSION_ << " required. "
             << cfgversion << " found.\n";
        return -1;
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

    if (b64pair_to_bin() != 0)
        return -1;

    return 0;
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
    for (string &peer : cfg.peers)
    {
        Value v;
        v.SetString(StringRef(peer.data()), allocator);
        peers.PushBack(v, allocator);
    }
    d.AddMember("peers", peers, allocator);

    Value unl(kArrayType);
    for (string &node : cfg.unl)
    {
        Value v;
        v.SetString(StringRef(node.data()), allocator);
        unl.PushBack(v, allocator);
    }
    d.AddMember("unl", unl, allocator);

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

int create_contract()
{
    if (boost::filesystem::exists(ctx.contractDir))
    {
        cerr << "Contract dir already exists. Cannot create contract at the same location.\n";
        return -1;
    }

    boost::filesystem::create_directories(ctx.configDir);
    boost::filesystem::create_directories(ctx.histDir);
    boost::filesystem::create_directories(ctx.stateDir);

    //Create config file with default settings.

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey);
    binpair_to_b64();

    cfg.listenip = "0.0.0.0";
    cfg.peerport = 22860;
    cfg.roundtime = 1000;
    cfg.pubport = 8080;
    cfg.pubmaxsize = 65536;
    cfg.pubmaxcpm = 100;
    save_config();

    cout << "Contract directory created at " << ctx.contractDir << endl;

    if (load_config() != 0)
        return -1;

    return 0;
}

void binpair_to_b64()
{
    shared::base64_encode((unsigned char *)cfg.pubkey.data(), crypto_sign_PUBLICKEYBYTES, cfg.pubkeyb64);
    shared::base64_encode((unsigned char *)cfg.seckey.data(), crypto_sign_SECRETKEYBYTES, cfg.seckeyb64);
}

int b64pair_to_bin()
{
    unsigned char decoded_pubkey[crypto_sign_PUBLICKEYBYTES];
    unsigned char decoded_seckey[crypto_sign_SECRETKEYBYTES];

    if (shared::base64_decode(cfg.pubkeyb64, decoded_pubkey, crypto_sign_PUBLICKEYBYTES) != 0)
    {
        cerr << "Error decoding base64 public key.\n";
        return -1;
    }

    if (shared::base64_decode(cfg.seckeyb64, decoded_seckey, crypto_sign_SECRETKEYBYTES) != 0)
    {
        cerr << "Error decoding base64 secret key.\n";
        return -1;
    }

    shared::replace_string_contents(cfg.pubkey, (char *)decoded_pubkey, crypto_sign_PUBLICKEYBYTES);
    shared::replace_string_contents(cfg.seckey, (char *)decoded_seckey, crypto_sign_SECRETKEYBYTES);
    return 0;
}

bool validate_config()
{
    if (cfg.pubkeyb64.empty() || cfg.seckeyb64.empty())
    {
        cerr << "Signing keys missing. Run with 'rekey' to generate new keys.\n";
        return false;
    }

    if (cfg.binary.empty() || cfg.listenip.empty() ||
        cfg.peerport == 0 || cfg.roundtime == 0 || cfg.pubport == 0 || cfg.pubmaxsize == 0 || cfg.pubmaxcpm == 0)
    {
        cerr << "Required configuration fields missing at " << ctx.configFile << endl;
        return false;
    }

    if (!boost::filesystem::exists(cfg.binary))
    {
        cerr << "Contract binary does not exist: " << cfg.binary << endl;
        return false;
    }

    //Sign and verify a sample to ensure we have a matching signing key pair.
    string msg = "hotpocket";
    string sigb64 = crypto::sign_b64(msg, cfg.seckeyb64);
    if (!crypto::verify_b64(msg, sigb64, cfg.pubkeyb64))
    {
        cerr << "Invalid signing keys. Run with 'rekey' to generate new keys.\n";
        return false;
    }

    return true;
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
}

bool validate_contract_dir_paths()
{
    string dirs[4] = {ctx.contractDir, ctx.configFile, ctx.histDir, ctx.stateDir};

    for (string &dir : dirs)
    {
        if (!boost::filesystem::exists(dir))
        {
            cerr << dir << " does not exist.\n";
            return false;
        }
    }

    return true;
}

bool is_schema_valid(Document &d)
{
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

    Document sd;
    sd.Parse(cfg_schema);
    SchemaDocument schema(sd);

    SchemaValidator validator(schema);
    return d.Accept(validator);
}

} // namespace conf