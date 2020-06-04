#include "pchheader.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "util.hpp"
#include "hplog.hpp"
#include <limits.h>
#include <stdlib.h>

namespace conf
{

// Global contract context struct exposed to the application.
contract_ctx ctx;

// Global configuration struct exposed to the application.
contract_config cfg;

const static char *MODE_OBSERVER = "observer";
const static char *MODE_PROPOSER = "proposer";

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
    const std::string portstr = std::to_string(cfg.peerport);

    cfg.peers.emplace(std::make_pair(SELF_HOST, cfg.peerport));

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
    binpair_to_hex();

    if (save_config() != 0)
        return -1;

    std::cout << "New signing keys generated at " << ctx.config_file << std::endl;

    return 0;
}

/**
 * Creates a new contract directory with the default contract config.
 * By the time this gets called, the 'ctx' struct must be populated.
 * This function makes use of the paths populated in the ctx.
 */
int create_contract()
{
    if (boost::filesystem::exists(ctx.contract_dir))
    {
        std::cout << "Contract dir already exists. Cannot create contract at the same location.\n";
        return -1;
    }

    boost::filesystem::create_directories(ctx.config_dir);
    boost::filesystem::create_directories(ctx.hist_dir);
    boost::filesystem::create_directories(ctx.state_rw_dir);

    //Create config file with default settings.

    //We populate the in-memory struct with default settings and then save it to the file.

    crypto::generate_signing_keys(cfg.pubkey, cfg.seckey);
    binpair_to_hex();

    cfg.startup_mode = OPERATING_MODE::PROPOSER;
    cfg.peerport = 22860;
    cfg.roundtime = 1000;
    cfg.pubport = 8080;

#ifndef NDEBUG
    cfg.loglevel = "debug";
#else
    cfg.loglevel = "warn";
#endif
    cfg.loggers.emplace("console");

    cfg.binary = "<your contract binary here>";

    //Save the default settings into the config file.
    if (save_config() != 0)
        return -1;

    std::cout << "Contract directory created at " << ctx.contract_dir << std::endl;

    return 0;
}

/**
 * Updates the contract context with directory paths based on provided base directory.
 * This is called after parsing HP command line arg in order to populate the ctx.
 */
void set_contract_dir_paths(std::string exepath, std::string basedir)
{
    if (exepath.empty())
    {
        // this code branch will never execute the way main is currently coded, but it might change in future
        std::cerr << "Executable path must be specified\n";
        exit(1);
    }

    if (basedir.empty())
    {
        // this code branch will never execute the way main is currently coded, but it might change in future
        std::cerr << "a contract directory must be specified\n";
        exit(1);
    }

    // resolving the path through realpath will remove any trailing slash if present
    basedir = util::realpath(basedir);

    ctx.exe_dir = boost::filesystem::path(util::realpath(exepath)).parent_path().string();
    ctx.websocketd_exe_path = ctx.exe_dir + "/" + "websocketd";
    ctx.websocat_exe_path = ctx.exe_dir + "/" + "websocat";
    ctx.hpfs_exe_path = ctx.exe_dir + "/" + "hpfs";

    ctx.contract_dir = basedir;
    ctx.config_dir = basedir + "/cfg";
    ctx.config_file = ctx.config_dir + "/hp.cfg";
    ctx.tls_key_file = ctx.config_dir + "/tlskey.pem";
    ctx.tls_cert_file = ctx.config_dir + "/tlscert.pem";
    ctx.hist_dir = basedir + "/hist";
    ctx.state_dir = basedir + "/state";
    ctx.state_rw_dir = ctx.state_dir + "/rw";
    ctx.log_dir = basedir + "/log";
}

/**
 * Reads the config file on disk and populates the in-memory 'cfg' struct.
 * 
 * @return 0 for successful loading of config. -1 for failure.
 */
int load_config()
{
    // Read the file into json document object.

    std::ifstream ifs(ctx.config_file);
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

    if (d["mode"] == MODE_OBSERVER)
        cfg.startup_mode = OPERATING_MODE::OBSERVER;
    else if (d["mode"] == MODE_PROPOSER)
        cfg.startup_mode = OPERATING_MODE::PROPOSER;
    else
    {
        std::cout << "Invalid mode. 'observer' or 'proposer' expected.\n";
        return -1;
    }
    cfg.current_mode = cfg.startup_mode;

    cfg.pubkeyhex = d["pubkeyhex"].GetString();
    cfg.seckeyhex = d["seckeyhex"].GetString();

    cfg.binary = d["binary"].GetString();
    cfg.binargs = d["binargs"].GetString();
    cfg.appbill = d["appbill"].GetString();
    cfg.appbillargs = d["appbillargs"].GetString();

    // Populate runtime contract execution args.
    if (!cfg.binargs.empty())
        boost::split(cfg.runtime_binexec_args, cfg.binargs, boost::is_any_of(" "));
    cfg.runtime_binexec_args.insert(cfg.runtime_binexec_args.begin(), (cfg.binary[0] == '/' ? cfg.binary : util::realpath(ctx.contract_dir + "/bin/" + cfg.binary)));

    // Populate runtime app bill args.
    if (!cfg.appbillargs.empty())
        boost::split(cfg.runtime_appbill_args, cfg.appbillargs, boost::is_any_of(" "));

    cfg.runtime_appbill_args.insert(cfg.runtime_appbill_args.begin(), (cfg.appbill[0] == '/' ? cfg.appbill : util::realpath(ctx.contract_dir + "/bin/" + cfg.appbill)));

    // Uncomment for docker-based execution.
    // std::string volumearg;
    // volumearg.append("type=bind,source=").append(ctx.state_dir).append(",target=/state");
    // const char *dockerargs[] = {"/usr/bin/docker", "run", "--rm", "-i", "--mount", volumearg.data(), cfg.binary.data()};
    // cfg.runtime_binexec_args.insert(cfg.runtime_binexec_args.begin(), std::begin(dockerargs), std::end(dockerargs));

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
            // Push the peer address and the port to peers set
            cfg.peers.emplace(std::make_pair(splitted_peers.front(), std::stoi(splitted_peers.back())));
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
    cfg.pubport = d["pubport"].GetInt();
    cfg.roundtime = d["roundtime"].GetInt();

    cfg.pubmaxsize = d["pubmaxsize"].GetUint64();
    cfg.pubmaxcpm = d["pubmaxcpm"].GetUint64();
    cfg.pubmaxbadmpm = d["pubmaxbadmpm"].GetUint64();
    cfg.pubmaxcons = d["pubmaxcons"].GetUint();

    cfg.peermaxsize = d["peermaxsize"].GetUint64();
    cfg.peermaxcpm = d["peermaxcpm"].GetUint64();
    cfg.peermaxdupmpm = d["peermaxdupmpm"].GetUint64();
    cfg.peermaxbadmpm = d["peermaxbadmpm"].GetUint64();
    cfg.peermaxbadsigpm = d["peermaxbadsigpm"].GetUint64();
    cfg.peermaxcons = d["peermaxcons"].GetUint();

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
    d.AddMember("mode", rapidjson::StringRef(cfg.startup_mode == OPERATING_MODE::OBSERVER ? MODE_OBSERVER : MODE_PROPOSER),
                allocator);

    d.AddMember("pubkeyhex", rapidjson::StringRef(cfg.pubkeyhex.data()), allocator);
    d.AddMember("seckeyhex", rapidjson::StringRef(cfg.seckeyhex.data()), allocator);
    d.AddMember("binary", rapidjson::StringRef(cfg.binary.data()), allocator);
    d.AddMember("binargs", rapidjson::StringRef(cfg.binargs.data()), allocator);
    d.AddMember("appbill", rapidjson::StringRef(cfg.appbill.data()), allocator);
    d.AddMember("appbillargs", rapidjson::StringRef(cfg.appbillargs.data()), allocator);

    rapidjson::Value peers(rapidjson::kArrayType);
    for (const auto &ipport_pair : cfg.peers)
    {
        rapidjson::Value v;
        const std::string concat_str = std::string(ipport_pair.first).append(":").append(std::to_string(ipport_pair.second));
        v.SetString(rapidjson::StringRef(concat_str.data()), allocator);
        peers.PushBack(v, allocator);
    }
    d.AddMember("peers", peers, allocator);

    rapidjson::Value unl(rapidjson::kArrayType);
    for (const auto &nodepk : cfg.unl)
    {
        rapidjson::Value v;
        std::string hex_pubkey;
        util::bin2hex(
            hex_pubkey,
            reinterpret_cast<const unsigned char *>(nodepk.data()),
            nodepk.length());

        v.SetString(rapidjson::StringRef(hex_pubkey.data()), allocator);
        unl.PushBack(v, allocator);
    }
    d.AddMember("unl", unl, allocator);

    d.AddMember("peerport", cfg.peerport, allocator);
    d.AddMember("pubport", cfg.pubport, allocator);
    d.AddMember("roundtime", cfg.roundtime, allocator);

    d.AddMember("pubmaxsize", cfg.pubmaxsize, allocator);
    d.AddMember("pubmaxcpm", cfg.pubmaxcpm, allocator);
    d.AddMember("pubmaxbadmpm", cfg.pubmaxbadmpm, allocator);
    d.AddMember("pubmaxcons", cfg.pubmaxcons, allocator);

    d.AddMember("peermaxsize", cfg.peermaxsize, allocator);
    d.AddMember("peermaxcpm", cfg.peermaxcpm, allocator);
    d.AddMember("peermaxdupmpm", cfg.peermaxdupmpm, allocator);
    d.AddMember("peermaxbadmpm", cfg.peermaxbadmpm, allocator);
    d.AddMember("peermaxbadsigpm", cfg.peermaxbadsigpm, allocator);
    d.AddMember("peermaxcons", cfg.peermaxcons, allocator);

    d.AddMember("loglevel", rapidjson::StringRef(cfg.loglevel.data()), allocator);
    rapidjson::Value loggers(rapidjson::kArrayType);
    for (std::string_view logger : cfg.loggers)
    {
        rapidjson::Value v;
        v.SetString(rapidjson::StringRef(logger.data()), allocator);
        loggers.PushBack(v, allocator);
    }
    d.AddMember("loggers", loggers, allocator);

    // Write the json doc to file.

    std::ofstream ofs(ctx.config_file);
    rapidjson::OStreamWrapper osw(ofs);

    rapidjson::PrettyWriter<rapidjson::OStreamWrapper> writer(osw);
    if (!d.Accept(writer))
    {
        std::cout << "Writing to config file failed. " << ctx.config_file << std::endl;
        return -1;
    }
    ofs.close();

    return 0;
}

/**
 * Decode current binary keys in 'cfg' and populate the it with hex keys.
 * 
 * @return Always returns 0.
 */
int binpair_to_hex()
{
    util::bin2hex(
        cfg.pubkeyhex,
        reinterpret_cast<const unsigned char *>(cfg.pubkey.data()),
        cfg.pubkey.length());

    util::bin2hex(
        cfg.seckeyhex,
        reinterpret_cast<const unsigned char *>(cfg.seckey.data()),
        cfg.seckey.length());

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

    bool fields_missing = false;

    fields_missing |= cfg.binary.empty() && std::cout << "Missing cfg field: binary\n";
    fields_missing |= cfg.peerport == 0 && std::cout << "Missing cfg field: peerport\n";
    fields_missing |= cfg.roundtime == 0 && std::cout << "Missing cfg field: roundtime\n";
    fields_missing |= cfg.pubport == 0 && std::cout << "Missing cfg field: pubport\n";
    fields_missing |= cfg.loglevel.empty() && std::cout << "Missing cfg field: loglevel\n";
    fields_missing |= cfg.loggers.empty() && std::cout << "Missing cfg field: loggers\n";

    if (fields_missing)
    {
        std::cout << "Required configuration fields missing at " << ctx.config_file << std::endl;
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

    //Sign and verify a sample message to ensure we have a matching signing key pair.
    const std::string msg = "hotpocket";
    const std::string sighex = crypto::sign_hex(msg, cfg.seckeyhex);
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
    const std::string paths[6] = {
        ctx.contract_dir,
        ctx.config_file,
        ctx.hist_dir,
        ctx.state_dir,
        ctx.tls_key_file,
        ctx.tls_cert_file};

    for (const std::string &path : paths)
    {
        if (!boost::filesystem::exists(path))
        {
            if (path == ctx.tls_key_file || path == ctx.tls_cert_file)
            {
                std::cout << path << " does not exist. Please provide self-signed certificates. Can generate using command\n"
                          << "openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem\n"
                          << "and add it to " + ctx.config_dir << std::endl;
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
int is_schema_valid(const rapidjson::Document &d)
{
    const char *cfg_schema =
        "{"
        "\"type\": \"object\","
        "\"required\": [ \"mode\", \"version\", \"pubkeyhex\", \"seckeyhex\", \"binary\", \"binargs\", \"appbill\", \"appbillargs\""
        ", \"peers\", \"unl\", \"pubport\", \"peerport\", \"roundtime\""
        ", \"pubmaxsize\", \"pubmaxcpm\", \"pubmaxbadmpm\", \"pubmaxcons\""
        ", \"peermaxsize\", \"peermaxcpm\", \"peermaxdupmpm\", \"peermaxbadmpm\", \"peermaxbadsigpm\", \"peermaxcons\""
        ", \"loglevel\", \"loggers\" ],"
        "\"properties\": {"
        "\"mode\": { \"type\": \"string\" },"
        "\"version\": { \"type\": \"string\" },"
        "\"pubkeyhex\": { \"type\": \"string\" },"
        "\"seckeyhex\": { \"type\": \"string\" },"
        "\"binary\": { \"type\": \"string\" },"
        "\"binargs\": { \"type\": \"string\" },"
        "\"appbill\": { \"type\": \"string\" },"
        "\"appbillargs\": { \"type\": \"string\" },"
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
        "\"pubmaxbadmpm\": { \"type\": \"integer\" },"

        "\"peermaxsize\": { \"type\": \"integer\" },"
        "\"peermaxcpm\": { \"type\": \"integer\" },"
        "\"peermaxdupmpm\": { \"type\": \"integer\" },"
        "\"peermaxbadmpm\": { \"type\": \"integer\" },"
        "\"peermaxbadsigpm\": { \"type\": \"integer\" },"

        "\"loglevel\": { \"type\": \"string\" },"
        "\"loggers\": {"
        "\"type\": \"array\","
        "\"items\": { \"type\": \"string\" }"
        "}"
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

void change_operating_mode(const OPERATING_MODE mode)
{
    // Do not allow to change the mode if the node was started as an observer.
    if (cfg.startup_mode == OPERATING_MODE::OBSERVER || cfg.current_mode == mode)
        return;

    cfg.current_mode = mode;

    if (mode == OPERATING_MODE::OBSERVER)
        LOG_INFO << "Switched to OBSERVER mode.";
    else
        LOG_INFO << "Switched back to PROPOSER mode.";
}

} // namespace conf
