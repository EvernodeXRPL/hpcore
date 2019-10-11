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
#include "conf.hpp"
#include "crypto.hpp"
#include "util.hpp"

using namespace std;
using namespace rapidjson;

namespace conf
{

// Global contract context struct exposed to the application.
contract_ctx ctx;

// Global configuration struct exposed to the application.
contract_config cfg;

/**
 * Loads and initializes the contract config for execution. Must be called once during application startup.
 * @return 0 for success. -1 for failure.
 */
int init()
{
    // The validations/loading needs to be in this order.
    // 1. Validate contract directories
    // 2. Read and load the contract config into memory
    // 3. Validate the loaded config values

    if (validate_contract_dir_paths() != 0 || load_config() != 0 || validate_config() != 0)
        return -1;

    return 0;
}

/**
 * Generates and saves new signing keys in the contract config.
 */
int rekey()
{
    // Load the contract config and re-save with the newly generated keys.

    if (load_config() != 0)
        return -1;

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey, cfg.keytype);
    if (binpair_to_b64() != 0)
        return -1;

    if (save_config() != 0)
        return -1;

    cout << "New signing keys generated at " << ctx.configFile << endl;

    return 0;
}

/**
 * Creates a new contract directory with the default contract config.
 * By the time this gets called, the 'ctx' struct must be populated.
 * This function makes use of the paths populated in the ctx.
 */
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

    //We populate the in-memory struct with default settings and then save it to the file.

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey, cfg.keytype);
    if (binpair_to_b64() != 0)
        return -1;

    cfg.listenip = "0.0.0.0";
    cfg.peerport = 22860;
    cfg.roundtime = 1000;
    cfg.pubport = 8080;
    cfg.pubmaxsize = 65536;
    cfg.pubmaxcpm = 100;

    //Save the default settings into the config file.
    if (save_config() != 0)
        return -1;

    cout << "Contract directory created at " << ctx.contractDir << endl;

    return 0;
}

/**
 * Updates the contract context with directory paths based on provided base directory.
 * This is called after parsing HP command line arg in order to populate the ctx.
 */
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

/**
 * Reads the config file on disk and populates the in-memory 'cfg' struct.
 * 
 * @return 0 for successful loading of config. -1 for failure.
 */
int load_config()
{
    // Read the file into json document object.

    ifstream ifs(ctx.configFile);
    IStreamWrapper isw(ifs);

    Document d;
    if (d.ParseStream(isw).HasParseError())
    {
        cerr << "Invalid config file format. Parser error at position " << d.GetErrorOffset() << endl;
        return -1;
    }
    else if (is_schema_valid(d) != 0)
    {
        cerr << "Invalid config file format.\n";
        return -1;
    }
    ifs.close();

    // Check whether the contract version is specified.
    string cfgversion = d["version"].GetString();
    if (cfgversion.empty())
    {
        cerr << "Contract config version missing.\n";
        return -1;
    }

    // Check whether this contract complies with the min version requirement.
    int verresult = util::version_compare(cfgversion, string(util::MIN_CONTRACT_VERSION));
    if (verresult == -1)
    {
        cerr << "Contract version too old. Minimum "
             << util::MIN_CONTRACT_VERSION << " required. "
             << cfgversion << " found.\n";
        return -1;
    }
    else if (verresult == -2)
    {
        cerr << "Malformed version string.\n";
        return -1;
    }

    // Load up the values into the struct.

    cfg.pubkeyb64 = d["pubkeyb64"].GetString();
    cfg.seckeyb64 = d["seckeyb64"].GetString();
    cfg.keytype = d["keytype"].GetString();
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

    // Convert the b64 keys to binary and keep for later use.
    if (b64pair_to_bin() != 0)
        return -1;

    return 0;
}

/**
 * Saves the current values of the 'cfg' struct into the config file.
 * 
 * @return 0 for successful save. -1 for failure.
 */
int save_config()
{
    // Popualte json document with 'cfg' values.

    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", StringRef(util::HP_VERSION), allocator);
    d.AddMember("pubkeyb64", StringRef(cfg.pubkeyb64.data()), allocator);
    d.AddMember("seckeyb64", StringRef(cfg.seckeyb64.data()), allocator);
    d.AddMember("keytype", StringRef(cfg.keytype.data()), allocator);
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


    // Write the json doc to file.

    ofstream ofs(ctx.configFile);
    OStreamWrapper osw(ofs);

    PrettyWriter<OStreamWrapper> writer(osw);
    if (!d.Accept(writer))
    {
        cerr << "Writing to config file failed. " << ctx.configFile << endl;
        return -1;
    }
    ofs.close();

    return 0;
}

/**
 * Decode current binary keys in 'cfg' and populate the it with base64 keys.
 * 
 * @return 0 for successful conversion. -1 for failure.
 */
int binpair_to_b64()
{
    if (util::base64_encode((unsigned char *)cfg.pubkey.data(), crypto_sign_PUBLICKEYBYTES, cfg.pubkeyb64) != 0)
    {
        cerr << "Error encoding public key bytes.\n";
        return -1;
    }

    if (util::base64_encode((unsigned char *)cfg.seckey.data(), crypto_sign_SECRETKEYBYTES, cfg.seckeyb64) != 0)
    {
        cerr << "Error encoding secret key bytes.\n";
        return -1;
    }

    return 0;
}

/**
 * Decode current base64 keys in 'cfg' and populate the it with binary keys.
 * 
 * @return 0 for successful conversion. -1 for failure.
 */
int b64pair_to_bin()
{
    unsigned char decoded_pubkey[crypto_sign_PUBLICKEYBYTES];
    unsigned char decoded_seckey[crypto_sign_SECRETKEYBYTES];

    if (util::base64_decode(cfg.pubkeyb64, decoded_pubkey, crypto_sign_PUBLICKEYBYTES) != 0)
    {
        cerr << "Error decoding base64 public key.\n";
        return -1;
    }

    if (util::base64_decode(cfg.seckeyb64, decoded_seckey, crypto_sign_SECRETKEYBYTES) != 0)
    {
        cerr << "Error decoding base64 secret key.\n";
        return -1;
    }

    // Assign the cfg pubkey/seckey fields with the decoded strings.
    cfg.pubkey = string((char *)decoded_pubkey, crypto_sign_PUBLICKEYBYTES);
    cfg.seckey = string((char *)decoded_seckey, crypto_sign_SECRETKEYBYTES);
    return 0;
}

/**
 * Validates the 'cfg' struct for invalid values.
 * 
 * @return 0 for successful validation. -1 for failure.
 */
int validate_config()
{
    // Check for non-empty signing keys.
    // We also check for key pair validity as well in the below code.
    if (cfg.pubkeyb64.empty() || cfg.seckeyb64.empty())
    {
        cerr << "Signing keys missing. Run with 'rekey' to generate new keys.\n";
        return -1;
    }

    // Other required fields.
    if (cfg.binary.empty() || cfg.listenip.empty() ||
        cfg.peerport == 0 || cfg.roundtime == 0 || cfg.pubport == 0 || cfg.pubmaxsize == 0 || cfg.pubmaxcpm == 0)
    {
        cerr << "Required configuration fields missing at " << ctx.configFile << endl;
        return -1;
    }

    // Check whether the contract binary actually exists.
    if (!boost::filesystem::exists(cfg.binary))
    {
        cerr << "Contract binary does not exist: " << cfg.binary << endl;
        return -1;
    }

    //Sign and verify a sample message to ensure we have a matching signing key pair.
    string msg = "hotpocket";
    string sigb64 = crypto::sign_b64(msg, cfg.seckeyb64);
    if (crypto::verify_b64(msg, sigb64, cfg.pubkeyb64) != 0)
    {
        cerr << "Invalid signing keys. Run with 'rekey' to generate new keys.\n";
        return -1;
    }

    return 0;
}

/**
 * Checks for the existence of all contract sub directories.
 * 
 * @return 0 for successful validation. -1 for failure.
 */
int validate_contract_dir_paths()
{
    string dirs[4] = {ctx.contractDir, ctx.configFile, ctx.histDir, ctx.stateDir};

    for (string &dir : dirs)
    {
        if (!boost::filesystem::exists(dir))
        {
            cerr << dir << " does not exist.\n";
            return -1;
        }
    }

    return 0;
}

/**
 * Validates the config json document schema.
 * 
 * @return 0 for successful validation. -1 for failure.
 */
int is_schema_valid(Document &d)
{
    const char *cfg_schema =
        "{"
        "\"type\": \"object\","
        "\"required\": [ \"version\", \"pubkeyb64\", \"seckeyb64\", \"keytype\", \"binary\", \"binargs\", \"listenip\""
        ", \"peers\", \"unl\", \"peerport\", \"roundtime\", \"pubport\", \"pubmaxsize\", \"pubmaxcpm\" ],"
        "\"properties\": {"
        "\"version\": { \"type\": \"string\" },"
        "\"pubkeyb64\": { \"type\": \"string\" },"
        "\"seckeyb64\": { \"type\": \"string\" },"
        "\"keytype\": { \"type\": \"string\" },"
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
    if (!d.Accept(validator))
        return -1;
    
    return 0;
}

} // namespace conf