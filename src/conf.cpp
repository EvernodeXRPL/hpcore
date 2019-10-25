#include <cstdio>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <experimental/filesystem>
#include <sodium.h>
#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>

#include <boost/algorithm/string.hpp>
#include "conf.hpp"
#include "crypto.hpp"
#include "util.hpp"

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

    // Append self peer to peer list.
    std::string portstr = std::to_string(cfg.peerport);
    std::string peerid = "0.0.0.0:" + portstr;
    cfg.peers.emplace(std::move(peerid), std::make_pair("0.0.0.0", portstr));

    // Append self pubkey to unl list.
    cfg.unl.emplace(cfg.pubkey);

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

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey);
    if (binpair_to_hex() != 0)
        return -1;

    if (save_config() != 0)
        return -1;

    std::cout << "New signing keys generated at " << ctx.configFile << std::endl;

    return 0;
}

/**
 * Creates a new contract directory with the default contract config.
 * By the time this gets called, the 'ctx' struct must be populated.
 * This function makes use of the paths populated in the ctx.
 */
int create_contract()
{
    if (std::experimental::filesystem::exists(ctx.contractDir))
    {
        std::cout << "Contract dir already exists. Cannot create contract at the same location.\n";
        return -1;
    }

    std::experimental::filesystem::create_directories(ctx.configDir);
    std::experimental::filesystem::create_directories(ctx.histDir);
    std::experimental::filesystem::create_directories(ctx.stateDir);

    //Create config file with default settings.

    //We populate the in-memory struct with default settings and then save it to the file.

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey);
    if (binpair_to_hex() != 0)
        return -1;

    cfg.listenip = "0.0.0.0";
    cfg.peerport = 22860;
    cfg.roundtime = 1000;
    cfg.pubport = 8080;
    cfg.pubmaxsize = 65536;
    cfg.pubmaxcpm = 100;

#ifndef NDEBUG
    cfg.loglevel = "debug";
#else
    cfg.loglevel = "warn";
#endif
    cfg.loggers.emplace("console");

    //Save the default settings into the config file.
    if (save_config() != 0)
        return -1;

    std::cout << "Contract directory created at " << ctx.contractDir << std::endl;

    return 0;
}

/**
 * Updates the contract context with directory paths based on provided base directory.
 * This is called after parsing HP command line arg in order to populate the ctx.
 */
void set_contract_dir_paths(std::string basedir)
{
    if (basedir[basedir.size() - 1] == '/')
        basedir = basedir.substr(0, basedir.size() - 1);

    ctx.contractDir = basedir;
    ctx.configDir = basedir + "/cfg";
    ctx.configFile = ctx.configDir + "/hp.cfg";
    ctx.tlsKeyFile = ctx.configDir + "/key.pem";
    ctx.tlsCertFile = ctx.configDir + "/cert.pem";
    ctx.histDir = basedir + "/hist";
    ctx.stateDir = basedir + "/state";
    ctx.logDir = basedir + "/log";
}

/**
 * Reads the config file on disk and populates the in-memory 'cfg' struct.
 * 
 * @return 0 for successful loading of config. -1 for failure.
 */
int load_config()
{
    // Read the file into json document object.

    std::ifstream ifs(ctx.configFile);
    rapidjson::IStreamWrapper isw(ifs);

    rapidjson::Document d;
    if (d.ParseStream(isw).HasParseError())
    {
        std::cout << "Invalid config file format. Parser error at position " << d.GetErrorOffset() << std::endl;
        return -1;
    }
    else if (is_schema_valid(d) != 0)
    {
        std::cout << "Invalid config file format.\n";
        return -1;
    }
    ifs.close();

    // Check whether the contract version is specified.
    std::string_view cfgversion = util::getsv(d["version"]);
    if (cfgversion.empty())
    {
        std::cout << "Contract config version missing.\n";
        return -1;
    }

    // Check whether this contract complies with the min version requirement.
    int verresult = util::version_compare(std::string(cfgversion), std::string(util::MIN_CONTRACT_VERSION));
    if (verresult == -1)
    {
        std::cout << "Contract version too old. Minimum "
                  << util::MIN_CONTRACT_VERSION << " required. "
                  << cfgversion << " found.\n";
        return -1;
    }
    else if (verresult == -2)
    {
        std::cout << "Malformed version string.\n";
        return -1;
    }

    // Load up the values into the struct.

    cfg.pubkeyhex = d["pubkeyhex"].GetString();
    cfg.seckeyhex = d["seckeyhex"].GetString();
    cfg.binary = d["binary"].GetString();
    cfg.binargs = d["binargs"].GetString();
    cfg.listenip = d["listenip"].GetString();

    // Storing peers in unordered map keyed by the concatenated address:port and also saving address and port
    // seperately to retrieve easily when handling peer connections.
    std::vector<std::string> splitted_peers;
    cfg.peers.clear();
    for (auto &v : d["peers"].GetArray())
    {
        const char *ipport_concat = v.GetString();
        // Split the address:port text into two
        boost::split(splitted_peers, ipport_concat, boost::is_any_of(":"));
        if (splitted_peers.size() == 2)
        {
        // Push the peer address and the port to peers array
        cfg.peers.emplace(std::make_pair(ipport_concat, std::make_pair(splitted_peers.front(), splitted_peers.back())));
        splitted_peers.clear();
        }
    }

    cfg.unl.clear();
    for (auto &nodepk : d["unl"].GetArray())
    {
        // Convert the public key hex of each node to binary and store it.
        std::string bin_pubkey;
        bin_pubkey.resize(crypto::PFXD_PUBKEY_BYTES);
        if (util::hex2bin(
                reinterpret_cast<unsigned char *>(bin_pubkey.data()),
                bin_pubkey.length(),
                nodepk.GetString()) != 0)
        {
            std::cerr << "Error decoding unl list.\n";
            return -1;
        }
        cfg.unl.emplace(bin_pubkey);
    }

    cfg.peerport = d["peerport"].GetInt();
    cfg.roundtime = d["roundtime"].GetInt();
    cfg.pubport = d["pubport"].GetInt();
    cfg.pubmaxsize = d["pubmaxsize"].GetInt();
    cfg.pubmaxcpm = d["pubmaxcpm"].GetInt();

    cfg.loglevel = d["loglevel"].GetString();
    cfg.loggers.clear();
    for (auto &v : d["loggers"].GetArray())
        cfg.loggers.emplace(v.GetString());

    // Convert the hex keys to binary and keep for later use.
    if (hexpair_to_bin() != 0)
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

    rapidjson::Document d;
    d.SetObject();
    rapidjson::Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", rapidjson::StringRef(util::HP_VERSION), allocator);
    d.AddMember("pubkeyhex", rapidjson::StringRef(cfg.pubkeyhex.data()), allocator);
    d.AddMember("seckeyhex", rapidjson::StringRef(cfg.seckeyhex.data()), allocator);
    d.AddMember("binary", rapidjson::StringRef(cfg.binary.data()), allocator);
    d.AddMember("binargs", rapidjson::StringRef(cfg.binargs.data()), allocator);
    d.AddMember("listenip", rapidjson::StringRef(cfg.listenip.data()), allocator);

    rapidjson::Value peers(rapidjson::kArrayType);
    for (auto &[ipport_concat, ipport_pair] : cfg.peers)
    {
        rapidjson::Value v;
        v.SetString(rapidjson::StringRef(ipport_concat.data()), allocator);
        peers.PushBack(v, allocator);
    }
    d.AddMember("peers", peers, allocator);

    rapidjson::Value unl(rapidjson::kArrayType);
    for (auto &nodepk : cfg.unl)
    {
        rapidjson::Value v;
        std::string hex_pubkey;
        if (util::bin2hex(
                hex_pubkey,
                reinterpret_cast<const unsigned char *>(nodepk.data()),
                nodepk.length()) != 0)
        {
            std::cerr << "Error encoding npl list.\n";
            return -1;
        }
        v.SetString(rapidjson::StringRef(hex_pubkey.data()), allocator);
        unl.PushBack(v, allocator);
    }
    d.AddMember("unl", unl, allocator);

    d.AddMember("peerport", cfg.peerport, allocator);
    d.AddMember("roundtime", cfg.roundtime, allocator);
    d.AddMember("pubport", cfg.pubport, allocator);
    d.AddMember("pubmaxsize", cfg.pubmaxsize, allocator);
    d.AddMember("pubmaxcpm", cfg.pubmaxcpm, allocator);

    d.AddMember("loglevel", rapidjson::StringRef(cfg.loglevel.data()), allocator);
    rapidjson::Value loggers(rapidjson::kArrayType);
    for (const std::string &logger : cfg.loggers)
    {
        rapidjson::Value v;
        v.SetString(rapidjson::StringRef(logger.data()), allocator);
        loggers.PushBack(v, allocator);
    }
    d.AddMember("loggers", loggers, allocator);

    // Write the json doc to file.

    std::ofstream ofs(ctx.configFile);
    rapidjson::OStreamWrapper osw(ofs);

    rapidjson::PrettyWriter<rapidjson::OStreamWrapper> writer(osw);
    if (!d.Accept(writer))
    {
        std::cout << "Writing to config file failed. " << ctx.configFile << std::endl;
        return -1;
    }
    ofs.close();

    return 0;
}

/**
 * Decode current binary keys in 'cfg' and populate the it with hex keys.
 * 
 * @return 0 for successful conversion. -1 for failure.
 */
int binpair_to_hex()
{
    if (util::bin2hex(
            cfg.pubkeyhex,
            reinterpret_cast<const unsigned char *>(cfg.pubkey.data()),
            cfg.pubkey.length()) != 0)
    {
        std::cout << "Error encoding public key bytes.\n";
        return -1;
    }

    if (util::bin2hex(
            cfg.seckeyhex,
            reinterpret_cast<const unsigned char *>(cfg.seckey.data()),
            cfg.seckey.length()) != 0)
    {
        std::cout << "Error encoding secret key bytes.\n";
        return -1;
    }

    return 0;
}

/**
 * Decode current hex keys in 'cfg' and populate the it with binary keys.
 * 
 * @return 0 for successful conversion. -1 for failure.
 */
int hexpair_to_bin()
{
    cfg.pubkey.resize(crypto::PFXD_PUBKEY_BYTES);
    if (util::hex2bin(
            reinterpret_cast<unsigned char *>(cfg.pubkey.data()),
            cfg.pubkey.length(),
            cfg.pubkeyhex) != 0)
    {
        std::cout << "Error decoding hex public key.\n";
        return -1;
    }

    cfg.seckey.resize(crypto::PFXD_SECKEY_BYTES);
    if (util::hex2bin(
            reinterpret_cast<unsigned char *>(cfg.seckey.data()),
            cfg.seckey.length(),
            cfg.seckeyhex) != 0)
    {
        std::cout << "Error decoding hex secret key.\n";
        return -1;
    }

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
    if (cfg.pubkeyhex.empty() || cfg.seckeyhex.empty())
    {
        std::cout << "Signing keys missing. Run with 'rekey' to generate new keys.\n";
        return -1;
    }

    // Other required fields.
    if (cfg.binary.empty() || cfg.listenip.empty() ||
        cfg.peerport == 0 || cfg.roundtime == 0 || cfg.pubport == 0 || cfg.pubmaxsize == 0 || cfg.pubmaxcpm == 0 ||
        cfg.loglevel.empty() || cfg.loggers.empty())
    {
        std::cout << "Required configuration fields missing at " << ctx.configFile << std::endl;
        return -1;
    }

    // Log settings
    const std::unordered_set<std::string> valid_loglevels({"debug", "info", "warn", "error"});
    if (valid_loglevels.count(cfg.loglevel) != 1)
    {
        std::cout << "Invalid loglevel configured. Valid values: debug|info|warn|error\n";
        return -1;
    }

    const std::unordered_set<std::string> valid_loggers({"console", "file"});
    for (const std::string &logger : cfg.loggers)
    {
        if (valid_loggers.count(logger) != 1)
        {
            std::cout << "Invalid logger. Valid values: console|file\n";
            return -1;
        }
    }

    // Check whether the contract binary actually exists.
    if (!std::experimental::filesystem::exists(cfg.binary))
    {
        std::cout << "Contract binary does not exist: " << cfg.binary << std::endl;
        return -1;
    }

    //Sign and verify a sample message to ensure we have a matching signing key pair.
    std::string msg = "hotpocket";
    std::string sighex = crypto::sign_hex(msg, cfg.seckeyhex);
    if (crypto::verify_hex(msg, sighex, cfg.pubkeyhex) != 0)
    {
        std::cout << "Invalid signing keys. Run with 'rekey' to generate new keys.\n";
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
    std::string paths[6] = {ctx.contractDir, ctx.configFile, ctx.histDir, ctx.stateDir, ctx.tlsKeyFile, ctx.tlsCertFile};

    for (std::string &path : paths)
    {
        if (!std::experimental::filesystem::exists(path))
        {
            if(path == ctx.tlsKeyFile || path == ctx.tlsCertFile)
            {
                std::cout << path << " does not exist. Please provide self-signed certificates. Can generate using command\n" <<
                    "openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem\n" <<
                    "and add it to "+ ctx.configDir << std::endl;
            }
            else
            {
                std::cout << path << " does not exist.\n";
            }

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
int is_schema_valid(rapidjson::Document &d)
{
    const char *cfg_schema =
        "{"
        "\"type\": \"object\","
        "\"required\": [ \"version\", \"pubkeyhex\", \"seckeyhex\", \"binary\", \"binargs\", \"listenip\""
        ", \"peers\", \"unl\", \"peerport\", \"roundtime\", \"pubport\", \"pubmaxsize\", \"pubmaxcpm\""
        ", \"loglevel\", \"loggers\" ],"
        "\"properties\": {"
        "\"version\": { \"type\": \"string\" },"
        "\"pubkeyhex\": { \"type\": \"string\" },"
        "\"seckeyhex\": { \"type\": \"string\" },"
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
        "\"pubmaxcpm\": { \"type\": \"integer\" },"
        "\"loglevel\": { \"type\": \"string\" },"
        "\"loggers\": {"
        "\"type\": \"array\","
        "\"items\": { \"type\": \"string\" }"
        "},"
        "}"
        "}";

    rapidjson::Document sd;
    sd.Parse(cfg_schema);
    rapidjson::SchemaDocument schema(sd);

    rapidjson::SchemaValidator validator(schema);
    if (!d.Accept(validator))
        return -1;

    return 0;
}

} // namespace conf