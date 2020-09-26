#include "pchheader.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "util.hpp"

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
        if (util::is_dir_exists(ctx.contract_dir))
        {
            std::cout << "Contract dir already exists. Cannot create contract at the same location.\n";
            return -1;
        }

        // Recursivly create contract directories.
        util::create_dir_tree_recursive(ctx.config_dir);
        util::create_dir_tree_recursive(ctx.hist_dir);
        util::create_dir_tree_recursive(ctx.state_rw_dir);

        //Create config file with default settings.

        //We populate the in-memory struct with default settings and then save it to the file.

        crypto::generate_signing_keys(cfg.pubkey, cfg.seckey);
        binpair_to_hex();

        cfg.startup_mode = OPERATING_MODE::PROPOSER;
        cfg.peerport = 22860;
        cfg.roundtime = 1000;
        cfg.pubport = 8080;
        cfg.pubtls = true;

#ifndef NDEBUG
        cfg.loglevel_type = conf::LOG_SEVERITY::DEBUG;
        cfg.loglevel = "dbg";
#else
        cfg.loglevel_type = conf::LOG_SEVERITY::WARN;
        cfg.loglevel = "wrn";
#endif

        cfg.loggers.emplace("console");
        cfg.loggers.emplace("file");
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
        exepath = util::realpath(exepath);

        // Take the parent directory path.
        ctx.exe_dir = dirname(exepath.data());

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
        jsoncons::json d;
        try
        {
            d = jsoncons::json::parse(ifs, jsoncons::strict_json_parsing());
        }
        catch (const std::exception &e)
        {
            std::cout << "Invalid config file format. " << e.what() << '\n';
            return -1;
        }
        ifs.close();

        // Check whether the contract version is specified.
        std::string_view cfgversion = d["version"].as<std::string_view>();
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

        cfg.pubkeyhex = d["pubkeyhex"].as<std::string>();
        cfg.seckeyhex = d["seckeyhex"].as<std::string>();

        cfg.binary = d["binary"].as<std::string>();
        cfg.binargs = d["binargs"].as<std::string>();
        cfg.appbill = d["appbill"].as<std::string>();
        cfg.appbillargs = d["appbillargs"].as<std::string>();

        // Populate runtime contract execution args.
        if (!cfg.binargs.empty())
            util::split_string(cfg.runtime_binexec_args, cfg.binargs, " ");
        cfg.runtime_binexec_args.insert(cfg.runtime_binexec_args.begin(), (cfg.binary[0] == '/' ? cfg.binary : util::realpath(ctx.contract_dir + "/bin/" + cfg.binary)));

        // Populate runtime app bill args.
        if (!cfg.appbillargs.empty())
            util::split_string(cfg.runtime_appbill_args, cfg.appbillargs, " ");

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
        for (auto &v : d["peers"].array_range())
        {
            const char *ipport_concat = v.as<const char *>();
            // Split the address:port text into two
            util::split_string(splitted_peers, ipport_concat, ":");
            if (splitted_peers.size() == 2)
            {
                // Push the peer address and the port to peers set
                cfg.peers.emplace(std::make_pair(splitted_peers.front(), std::stoi(splitted_peers.back())));
                splitted_peers.clear();
            }
        }

        cfg.unl.clear();
        for (auto &nodepk : d["unl"].array_range())
        {
            // Convert the public key hex of each node to binary and store it.
            std::string bin_pubkey;
            bin_pubkey.resize(crypto::PFXD_PUBKEY_BYTES);
            if (util::hex2bin(
                    reinterpret_cast<unsigned char *>(bin_pubkey.data()),
                    bin_pubkey.length(),
                    nodepk.as<std::string_view>()) != 0)
            {
                std::cerr << "Error decoding unl list.\n";
                return -1;
            }
            cfg.unl.emplace(bin_pubkey);
        }

        cfg.peerport = d["peerport"].as<int>();
        cfg.pubport = d["pubport"].as<int>();
        cfg.roundtime = d["roundtime"].as<int>();

        if (d.contains("pubtls")) // For backwards compatibility.
            cfg.pubtls = d["pubtls"].as<bool>();

        cfg.pubmaxsize = d["pubmaxsize"].as<uint64_t>();
        cfg.pubmaxcpm = d["pubmaxcpm"].as<uint64_t>();
        cfg.pubmaxbadmpm = d["pubmaxbadmpm"].as<uint64_t>();
        cfg.pubmaxcons = d["pubmaxcons"].as<unsigned int>();

        cfg.peermaxsize = d["peermaxsize"].as<uint64_t>();
        cfg.peermaxcpm = d["peermaxcpm"].as<uint64_t>();
        cfg.peermaxdupmpm = d["peermaxdupmpm"].as<uint64_t>();
        cfg.peermaxbadmpm = d["peermaxbadmpm"].as<uint64_t>();
        cfg.peermaxbadsigpm = d["peermaxbadsigpm"].as<uint64_t>();
        cfg.peermaxcons = d["peermaxcons"].as<unsigned int>();

        cfg.loglevel = d["loglevel"].as<std::string>();
        cfg.loglevel_type = get_loglevel_type(cfg.loglevel);
        cfg.loggers.clear();
        for (auto &v : d["loggers"].array_range())
            cfg.loggers.emplace(v.as<std::string>());

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
        // ojson is used instead of json to preserve insertion order
        jsoncons::ojson d;
        d.insert_or_assign("version", util::HP_VERSION);
        d.insert_or_assign("mode", cfg.startup_mode == OPERATING_MODE::OBSERVER ? MODE_OBSERVER : MODE_PROPOSER);

        d.insert_or_assign("pubkeyhex", cfg.pubkeyhex.data());
        d.insert_or_assign("seckeyhex", cfg.seckeyhex.data());
        d.insert_or_assign("binary", cfg.binary.data());
        d.insert_or_assign("binargs", cfg.binargs.data());
        d.insert_or_assign("appbill", cfg.appbill.data());
        d.insert_or_assign("appbillargs", cfg.appbillargs.data());

        jsoncons::ojson peers(jsoncons::json_array_arg);
        for (const auto &ipport_pair : cfg.peers)
        {
            const std::string concat_str = std::string(ipport_pair.first).append(":").append(std::to_string(ipport_pair.second));
            peers.push_back(concat_str);
        }
        d.insert_or_assign("peers", peers);

        jsoncons::ojson unl(jsoncons::json_array_arg);
        for (const auto &nodepk : cfg.unl)
        {
            std::string hex_pubkey;
            util::bin2hex(
                hex_pubkey,
                reinterpret_cast<const unsigned char *>(nodepk.data()),
                nodepk.length());
            unl.push_back(hex_pubkey);
        }
        d.insert_or_assign("unl", unl);

        d.insert_or_assign("peerport", cfg.peerport);
        d.insert_or_assign("pubport", cfg.pubport);
        d.insert_or_assign("roundtime", cfg.roundtime);

        d.insert_or_assign("pubtls", cfg.pubtls);
        d.insert_or_assign("pubmaxsize", cfg.pubmaxsize);
        d.insert_or_assign("pubmaxcpm", cfg.pubmaxcpm);
        d.insert_or_assign("pubmaxbadmpm", cfg.pubmaxbadmpm);
        d.insert_or_assign("pubmaxcons", cfg.pubmaxcons);

        d.insert_or_assign("peermaxsize", cfg.peermaxsize);
        d.insert_or_assign("peermaxcpm", cfg.peermaxcpm);
        d.insert_or_assign("peermaxdupmpm", cfg.peermaxdupmpm);
        d.insert_or_assign("peermaxbadmpm", cfg.peermaxbadmpm);
        d.insert_or_assign("peermaxbadsigpm", cfg.peermaxbadsigpm);
        d.insert_or_assign("peermaxcons", cfg.peermaxcons);

        d.insert_or_assign("loglevel", cfg.loglevel);

        jsoncons::ojson loggers(jsoncons::json_array_arg);
        for (std::string_view logger : cfg.loggers)
        {
            loggers.push_back(logger.data());
        }
        d.insert_or_assign("loggers", loggers);

        // Write the json doc to file.

        std::ofstream ofs(ctx.config_file);
        try
        {
            ofs << jsoncons::pretty_print(d);
        }
        catch (const std::exception &e)
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
        const std::unordered_set<std::string> valid_loglevels({"dbg", "inf", "wrn", "err"});
        if (valid_loglevels.count(cfg.loglevel) != 1)
        {
            std::cout << "Invalid loglevel configured. Valid values: dbg|inf|wrn|err\n";
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
            if (!util::is_file_exists(path) && !util::is_dir_exists(path))
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

    /**
     * Convert string to Log Severity enum type.
     * @param severity log severity code.
     * @return log severity type.
    */
    LOG_SEVERITY get_loglevel_type(std::string_view severity)
    {
        if (severity == "dbg")
            return LOG_SEVERITY::DEBUG;
        else if (severity == "wrn")
            return LOG_SEVERITY::WARN;
        else if (severity == "inf")
            return LOG_SEVERITY::INFO;
        else
            return LOG_SEVERITY::ERROR;
    }
} // namespace conf
