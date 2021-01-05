#include "pchheader.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "hpfs/hpfs.hpp"
#include "util/util.hpp"

namespace conf
{

    // Global contract context struct exposed to the application.
    contract_ctx ctx;

    // Global configuration struct exposed to the application.
    contract_config cfg;

    // Stores the initial startup mode of the node.
    ROLE startup_mode;

    const static char *ROLE_OBSERVER = "observer";
    const static char *ROLE_VALIDATOR = "validator";

    const static char *PUBLIC = "public";
    const static char *PRIVATE = "private";

    const static char *PATCH_FILE_NAME = "patch.cfg"; // Config patch filename.

    bool init_success = false;

    /**
     * Loads and initializes the contract config for execution. Must be called once during application startup.
     * @return 0 for success. -1 for failure.
     */
    int init()
    {
        // The validations/loading needs to be in this order.
        // 1. Validate contract directories
        // 2. Read and load the contract config into memory
        // 3. Update contract config if patch file exists.
        // 4. Validate the loaded config values
        // 5. Locking the config file at the startup.

        if (validate_contract_dir_paths() == -1 ||
            read_config(cfg) == -1 ||
            apply_patch_changes(cfg.contract) == -1 ||
            validate_config(cfg) == -1 ||
            set_config_lock() == -1)
        {
            return -1;
        }

        init_success = true;
        return 0;
    }

    /**
     * Cleanup any resources.
     */
    void deinit()
    {
        if (init_success)
        {
            // Releases the config file lock at the termination.
            release_config_lock();
        }
    }

    /**
     * Generates and saves new signing keys in the contract config.
     */
    int rekey()
    {
        // Locking the config file at the startup. To check whether there's any already running hp instances.
        if (set_config_lock() == -1)
            return -1;

        // Load the contract config and re-save with the newly generated keys.
        contract_config cfg = {};
        if (read_config(cfg) != 0)
            return -1;

        crypto::generate_signing_keys(cfg.node.public_key, cfg.node.private_key);
        cfg.node.public_key_hex = util::to_hex(cfg.node.public_key);
        cfg.node.private_key_hex = util::to_hex(cfg.node.private_key);

        if (write_config(cfg) != 0)
            return -1;

        std::cout << "New signing keys generated at " << ctx.config_file << std::endl;

        // Releases the config file lock at the termination.
        release_config_lock();

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
            std::cerr << "Contract dir already exists. Cannot create contract at the same location.\n";
            return -1;
        }

        // Recursivly create contract directories.
        util::create_dir_tree_recursive(ctx.config_dir);
        util::create_dir_tree_recursive(ctx.hist_dir);
        util::create_dir_tree_recursive(ctx.full_hist_dir);
        util::create_dir_tree_recursive(ctx.log_dir);
        util::create_dir_tree_recursive(ctx.state_dir);

        // Creating state seed dir in advance so hpfs doesn't cause mkdir race conditions during first-run.
        util::create_dir_tree_recursive(ctx.state_dir + "/seed");

        //Create config file with default settings.

        //We populate the in-memory struct with default settings and then save it to the file.

        contract_config cfg = {};

        crypto::generate_signing_keys(cfg.node.public_key, cfg.node.private_key);
        cfg.node.public_key_hex = util::to_hex(cfg.node.public_key);
        cfg.node.private_key_hex = util::to_hex(cfg.node.private_key);

        cfg.hp_version = util::HP_VERSION;

        cfg.node.role = ROLE::VALIDATOR;
        cfg.node.full_history = false;

        cfg.contract.id = crypto::generate_uuid();
        cfg.contract.version = "1.0";
        //Add self pubkey to the unl.
        cfg.contract.unl.emplace(cfg.node.public_key);
        cfg.contract.bin_path = "<your contract binary here>";
        cfg.contract.roundtime = 1000;
        cfg.contract.is_consensus_public = false;
        cfg.contract.is_npl_public = false;

        cfg.mesh.port = 22860;
        cfg.mesh.msg_forwarding = false;
        cfg.mesh.idle_timeout = 120;
        cfg.mesh.peer_discovery.enabled = false;
        cfg.mesh.peer_discovery.interval = 30000;

        cfg.user.port = 8080;
        cfg.user.idle_timeout = 0;

        cfg.log.loglevel_type = conf::LOG_SEVERITY::WARN;
        cfg.log.loglevel = "inf";
        cfg.log.loggers.emplace("console");
        cfg.log.loggers.emplace("file");

        //Save the default settings into the config file.
        if (write_config(cfg) != 0)
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

        ctx.hpws_exe_path = ctx.exe_dir + "/" + "hpws";
        ctx.hpfs_exe_path = ctx.exe_dir + "/" + "hpfs";

        ctx.contract_dir = basedir;
        ctx.config_dir = basedir + "/cfg";
        ctx.config_file = ctx.config_dir + "/hp.cfg";
        ctx.tls_key_file = ctx.config_dir + "/tlskey.pem";
        ctx.tls_cert_file = ctx.config_dir + "/tlscert.pem";
        ctx.hist_dir = basedir + "/hist";
        ctx.full_hist_dir = basedir + "/fullhist";
        ctx.state_dir = basedir + "/state";
        ctx.state_rw_dir = ctx.state_dir + "/rw";
        ctx.state_serve_dir = ctx.state_dir + "/ss";
        ctx.log_dir = basedir + "/log";
    }

    int persist_unl_update(const std::set<std::string> &updated_unl)
    {
        contract_config cfg = {};
        if (read_config(cfg) == -1)
            return -1;

        cfg.contract.unl = updated_unl;

        if (write_config(cfg) == -1)
            return -1;

        return 0;
    }

    /**
     * Reads the config file on disk and populates the in-memory 'cfg' struct.
     * @return 0 for successful loading of config. -1 for failure.
     */
    int read_config(contract_config &cfg)
    {
        // Read the config file into json document object.

        std::ifstream ifs(ctx.config_file);
        jsoncons::json d;
        try
        {
            d = jsoncons::json::parse(ifs, jsoncons::strict_json_parsing());
        }
        catch (const std::exception &e)
        {
            std::cerr << "Invalid config file format. " << e.what() << '\n';
            return -1;
        }
        ifs.close();

        try
        {
            // Check whether the hp version is specified.
            cfg.hp_version = d["hp_version"].as<std::string>();
            if (cfg.hp_version.empty())
            {
                std::cerr << "Contract config HP version missing.\n";
                return -1;
            }

            // Check whether this config complies with the min version requirement.
            int verresult = util::version_compare(cfg.hp_version, std::string(util::MIN_CONFIG_VERSION));
            if (verresult == -1)
            {
                std::cerr << "Config version too old. Minimum "
                          << util::MIN_CONFIG_VERSION << " required. "
                          << cfg.hp_version << " found.\n";
                return -1;
            }
            else if (verresult == -2)
            {
                std::cerr << "Malformed version string.\n";
                return -1;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Required config field hp_version missing at " << ctx.config_file << std::endl;
            return -1;
        }

        // node
        {
            try
            {
                const jsoncons::json &node = d["node"];
                cfg.node.public_key_hex = node["public_key"].as<std::string>();
                cfg.node.private_key_hex = node["private_key"].as<std::string>();

                // Convert the hex keys to binary.
                cfg.node.public_key = util::to_bin(cfg.node.public_key_hex);
                if (cfg.node.public_key.empty())
                {
                    std::cerr << "Error decoding hex public key.\n";
                    return -1;
                }

                cfg.node.private_key = util::to_bin(cfg.node.private_key_hex);
                if (cfg.node.private_key.empty())
                {
                    std::cerr << "Error decoding hex private key.\n";
                    return -1;
                }

                if (node["role"] == ROLE_OBSERVER)
                    cfg.node.role = ROLE::OBSERVER;
                else if (node["role"] == ROLE_VALIDATOR)
                    cfg.node.role = ROLE::VALIDATOR;
                else
                {
                    std::cerr << "Invalid mode. 'observer' or 'validator' expected.\n";
                    return -1;
                }
                startup_mode = cfg.node.role;
            }
            catch (const std::exception &e)
            {
                std::cerr << "Required node config field " << extract_missing_field(e.what()) << " missing at " << ctx.config_file << std::endl;
                return -1;
            }
        }

        // contract
        {
            try
            {
                const jsoncons::json &contract = d["contract"];
                cfg.contract.id = contract["id"].as<std::string>();
                cfg.contract.version = contract["version"].as<std::string>();
                if (cfg.contract.id.empty())
                {
                    std::cerr << "Contract id not specified.\n";
                    return -1;
                }
                else if (cfg.contract.version.empty())
                {
                    std::cerr << "Contract version not specified.\n";
                    return -1;
                }
                cfg.contract.unl.clear();
                for (auto &nodepk : contract["unl"].array_range())
                {
                    // Convert the public key hex of each node to binary and store it.
                    const std::string bin_pubkey = util::to_bin(nodepk.as<std::string_view>());
                    if (bin_pubkey.empty())
                    {
                        std::cerr << "Error decoding unl list.\n";
                        return -1;
                    }
                    cfg.contract.unl.emplace(bin_pubkey);
                }
                cfg.contract.bin_path = contract["bin_path"].as<std::string>();
                cfg.contract.bin_args = contract["bin_args"].as<std::string>();
                cfg.contract.roundtime = contract["roundtime"].as<uint16_t>();

                if (contract["consensus"] != PUBLIC && contract["consensus"] != PRIVATE)
                {
                    std::cerr << "Invalid consensus flag configured. Valid values: public|private\n";
                    return -1;
                }
                cfg.contract.is_consensus_public = contract["consensus"] == PUBLIC;

                if (contract["npl"] != PUBLIC && contract["npl"] != PRIVATE)
                {
                    std::cerr << "Invalid npl flag configured. Valid values: public|private\n";
                    return -1;
                }
                cfg.contract.is_npl_public = contract["npl"] == PUBLIC;
                if (!contract["appbill"].contains("mode"))
                {
                    std::cerr << "Required contract appbill config field mode missing at " << ctx.config_file << std::endl;
                    return -1;
                }
                cfg.contract.appbill.mode = contract["appbill"]["mode"].as<std::string>();
                if (!contract["appbill"].contains("bin_args"))
                {
                    std::cerr << "Required contract appbill config field bin_args missing at " << ctx.config_file << std::endl;
                    return -1;
                }
                cfg.contract.appbill.bin_args = contract["appbill"]["bin_args"].as<std::string>();
            }
            catch (const std::exception &e)
            {
                std::cerr << "Required contract config field " << extract_missing_field(e.what()) << " missing at " << ctx.config_file << std::endl;
                return -1;
            }
            // Populate runtime contract execution args.
            if (!cfg.contract.bin_args.empty())
                util::split_string(cfg.contract.runtime_binexec_args, cfg.contract.bin_args, " ");
            cfg.contract.runtime_binexec_args.insert(cfg.contract.runtime_binexec_args.begin(), (cfg.contract.bin_path[0] == '/' ? cfg.contract.bin_path : util::realpath(ctx.contract_dir + "/bin/" + cfg.contract.bin_path)));

            // Populate runtime app bill args.
            if (!cfg.contract.appbill.bin_args.empty())
                util::split_string(cfg.contract.appbill.runtime_args, cfg.contract.appbill.bin_args, " ");

            cfg.contract.appbill.runtime_args.insert(cfg.contract.appbill.runtime_args.begin(), (cfg.contract.appbill.mode[0] == '/' ? cfg.contract.appbill.mode : util::realpath(ctx.contract_dir + "/bin/" + cfg.contract.appbill.mode)));

            // Uncomment for docker-based execution.
            // std::string volumearg;
            // volumearg.append("type=bind,source=").append(ctx.state_dir).append(",target=/state");
            // const char *dockerargs[] = {"/usr/bin/docker", "run", "--rm", "-i", "--mount", volumearg.data(), cfg.contract.bin_path.data()};
            // cfg.contract.runtime_binexec_args.insert(cfg.contract.runtime_binexec_args.begin(), std::begin(dockerargs), std::end(dockerargs));
        }

        // mesh
        {
            try
            {
                const jsoncons::json &mesh = d["mesh"];
                cfg.mesh.port = mesh["port"].as<uint16_t>();
                // Storing peers in unordered map keyed by the concatenated address:port and also saving address and port
                // seperately to retrieve easily when handling peer connections.
                std::vector<std::string> splitted_peers;
                cfg.mesh.known_peers.clear();
                for (auto &v : mesh["known_peers"].array_range())
                {
                    const char *ipport_concat = v.as<const char *>();
                    // Split the address:port text into two
                    util::split_string(splitted_peers, ipport_concat, ":");

                    // Push the peer address and the port to peers set
                    if (splitted_peers.size() != 2)
                    {
                        std::cerr << "Invalid peer: " << ipport_concat << "\n";
                        return -1;
                    }

                    peer_properties peer;
                    peer.ip_port.host_address = splitted_peers.front();
                    peer.ip_port.port = std::stoi(splitted_peers.back());

                    cfg.mesh.known_peers.push_back(peer);
                    splitted_peers.clear();
                }
                cfg.mesh.msg_forwarding = mesh["msg_forwarding"].as<bool>();
                cfg.mesh.max_connections = mesh["max_connections"].as<uint16_t>();
                cfg.mesh.max_known_connections = mesh["max_known_connections"].as<uint16_t>();
                // If max_connections is greater than max_known_connections then show error and stop execution.
                if (cfg.mesh.max_known_connections > cfg.mesh.max_connections)
                {
                    std::cerr << "Invalid configuration values: mesh max_known_connections count should not exceed mesh max_connections." << '\n';
                    return -1;
                }
                cfg.mesh.max_bytes_per_msg = mesh["max_bytes_per_msg"].as<uint64_t>();
                cfg.mesh.max_bytes_per_min = mesh["max_bytes_per_min"].as<uint64_t>();
                cfg.mesh.max_bad_msgs_per_min = mesh["max_bad_msgs_per_min"].as<uint64_t>();
                cfg.mesh.max_bad_msgsigs_per_min = mesh["max_bad_msgsigs_per_min"].as<uint64_t>();
                cfg.mesh.max_dup_msgs_per_min = mesh["max_dup_msgs_per_min"].as<uint64_t>();
                cfg.mesh.idle_timeout = mesh["idle_timeout"].as<uint16_t>();
                if (!mesh["peer_discovery"].contains("interval"))
                {
                    std::cerr << "Required mesh peer discovery config field interval missing at " << ctx.config_file << std::endl;
                    return -1;
                }
                cfg.mesh.peer_discovery.interval = mesh["peer_discovery"]["interval"].as<uint16_t>();
                if (!mesh["peer_discovery"].contains("enabled"))
                {
                    std::cerr << "Required mesh peer discovery config field enabled missing at " << ctx.config_file << std::endl;
                    return -1;
                }
                cfg.mesh.peer_discovery.enabled = mesh["peer_discovery"]["enabled"].as<bool>();
            }
            catch (const std::exception &e)
            {
                std::cerr << "Required mesh config field " << extract_missing_field(e.what()) << " missing at " << ctx.config_file << std::endl;
                return -1;
            }
        }

        // user
        {
            try
            {
                const jsoncons::json &user = d["user"];
                cfg.user.port = user["port"].as<uint16_t>();
                cfg.user.max_connections = user["max_connections"].as<unsigned int>();
                cfg.user.max_bytes_per_msg = user["max_bytes_per_msg"].as<uint64_t>();
                cfg.user.max_bytes_per_min = user["max_bytes_per_min"].as<uint64_t>();
                cfg.user.max_bad_msgs_per_min = user["max_bad_msgs_per_min"].as<uint64_t>();
                cfg.user.idle_timeout = user["idle_timeout"].as<uint16_t>();
                cfg.user.enable_user_connections = user["enable_user_connections"].as<bool>();
            }
            catch (const std::exception &e)
            {
                std::cerr << "Required user config field " << extract_missing_field(e.what()) << " missing at " << ctx.config_file << std::endl;
                return -1;
            }
        }

        // log
        {
            try
            {
                const jsoncons::json &log = d["log"];
                cfg.log.loglevel = log["loglevel"].as<std::string>();
                cfg.log.loglevel_type = get_loglevel_type(cfg.log.loglevel);
                cfg.log.loggers.clear();
                for (auto &v : log["loggers"].array_range())
                    cfg.log.loggers.emplace(v.as<std::string>());
            }
            catch (const std::exception &e)
            {
                std::cerr << "Required log config field " << extract_missing_field(e.what()) << " missing at " << ctx.config_file << std::endl;
                return -1;
            }
        }

        return 0;
    }

    /**
     * Saves the provided 'cfg' struct into the config file.
     * @return 0 for successful save. -1 for failure.
     */
    int write_config(const contract_config &cfg)
    {
        // Popualte json document with 'cfg' values.
        // ojson is used instead of json to preserve insertion order.
        jsoncons::ojson d;
        d.insert_or_assign("hp_version", cfg.hp_version);

        // Node configs.
        jsoncons::ojson node_config;
        node_config.insert_or_assign("public_key", cfg.node.public_key_hex);
        node_config.insert_or_assign("private_key", cfg.node.private_key_hex);
        node_config.insert_or_assign("role", cfg.node.role == ROLE::OBSERVER ? ROLE_OBSERVER : ROLE_VALIDATOR);
        // node_config.insert_or_assign("full_history", cfg.node.full_history);
        d.insert_or_assign("node", node_config);

        // Contract configs.
        jsoncons::ojson contract;
        contract.insert_or_assign("id", cfg.contract.id);
        contract.insert_or_assign("version", cfg.contract.version);
        jsoncons::ojson unl(jsoncons::json_array_arg);
        for (const auto &nodepk : cfg.contract.unl)
        {
            unl.push_back(util::to_hex(nodepk));
        }
        contract.insert_or_assign("unl", unl);
        contract.insert_or_assign("bin_path", cfg.contract.bin_path);
        contract.insert_or_assign("bin_args", cfg.contract.bin_args);
        contract.insert_or_assign("roundtime", cfg.contract.roundtime);
        contract.insert_or_assign("consensus", cfg.contract.is_consensus_public ? PUBLIC : PRIVATE);
        contract.insert_or_assign("npl", cfg.contract.is_npl_public ? PUBLIC : PRIVATE);

        jsoncons::ojson appbill;
        appbill.insert_or_assign("mode", cfg.contract.appbill.mode);
        appbill.insert_or_assign("bin_args", cfg.contract.appbill.bin_args);

        contract.insert_or_assign("appbill", appbill);
        d.insert_or_assign("contract", contract);

        // Mesh configs.
        jsoncons::ojson mesh_config;
        mesh_config.insert_or_assign("port", cfg.mesh.port);

        jsoncons::ojson peers(jsoncons::json_array_arg);
        for (const auto &peer : cfg.mesh.known_peers)
        {
            const std::string concat_str = std::string(peer.ip_port.host_address).append(":").append(std::to_string(peer.ip_port.port));
            peers.push_back(concat_str);
        }
        mesh_config.insert_or_assign("known_peers", peers);
        mesh_config.insert_or_assign("msg_forwarding", cfg.mesh.msg_forwarding);
        mesh_config.insert_or_assign("max_connections", cfg.mesh.max_connections);
        mesh_config.insert_or_assign("max_known_connections", cfg.mesh.max_known_connections);
        mesh_config.insert_or_assign("max_bytes_per_msg", cfg.mesh.max_bytes_per_msg);
        mesh_config.insert_or_assign("max_bytes_per_min", cfg.mesh.max_bytes_per_min);
        mesh_config.insert_or_assign("max_bad_msgs_per_min", cfg.mesh.max_bad_msgs_per_min);
        mesh_config.insert_or_assign("max_bad_msgsigs_per_min", cfg.mesh.max_bad_msgsigs_per_min);
        mesh_config.insert_or_assign("max_dup_msgs_per_min", cfg.mesh.max_dup_msgs_per_min);
        mesh_config.insert_or_assign("idle_timeout", cfg.mesh.idle_timeout);

        jsoncons::ojson peer_discovery_config;
        peer_discovery_config.insert_or_assign("enabled", cfg.mesh.peer_discovery.enabled);
        peer_discovery_config.insert_or_assign("interval", cfg.mesh.peer_discovery.interval);

        mesh_config.insert_or_assign("peer_discovery", peer_discovery_config);
        d.insert_or_assign("mesh", mesh_config);

        // User configs.
        jsoncons::ojson user_config;
        user_config.insert_or_assign("port", cfg.user.port);
        user_config.insert_or_assign("idle_timeout", cfg.user.idle_timeout);
        user_config.insert_or_assign("max_bytes_per_msg", cfg.user.max_bytes_per_msg);
        user_config.insert_or_assign("max_bytes_per_min", cfg.user.max_bytes_per_min);
        user_config.insert_or_assign("max_bad_msgs_per_min", cfg.user.max_bad_msgs_per_min);
        user_config.insert_or_assign("max_connections", cfg.user.max_connections);
        user_config.insert_or_assign("enable_user_connections", cfg.user.enable_user_connections);
        d.insert_or_assign("user", user_config);

        // Log configs.
        jsoncons::ojson log_config;
        log_config.insert_or_assign("loglevel", cfg.log.loglevel);

        jsoncons::ojson loggers(jsoncons::json_array_arg);
        for (std::string_view logger : cfg.log.loggers)
        {
            loggers.push_back(logger);
        }
        log_config.insert_or_assign("loggers", loggers);
        d.insert_or_assign("log", log_config);

        // Write the json doc to file.
        std::ofstream ofs(ctx.config_file);
        try
        {
            jsoncons::json_options options;
            options.object_array_line_splits(jsoncons::line_split_kind::multi_line);
            ofs << jsoncons::pretty_print(d, options);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Writing to config file failed. " << ctx.config_file << std::endl;
            ofs.close();
            return -1;
        }
        ofs.close();

        return 0;
    }

    /**
     * Validates the 'cfg' struct for invalid values.
     *
     * @return 0 for successful validation. -1 for failure.
     */
    int validate_config(const contract_config &cfg)
    {
        // Check for non-empty signing keys.
        // We also check for key pair validity as well in the below code.
        if (cfg.node.public_key_hex.empty() || cfg.node.private_key_hex.empty())
        {
            std::cerr << "Signing keys missing. Run with 'rekey' to generate new keys.\n";
            return -1;
        }

        // Other required fields.

        bool fields_missing = false;

        fields_missing |= cfg.contract.bin_path.empty() && std::cerr << "Missing cfg field: bin_path\n";
        fields_missing |= cfg.contract.roundtime == 0 && std::cerr << "Missing cfg field: roundtime\n";
        fields_missing |= cfg.contract.unl.empty() && std::cerr << "Missing cfg field: unl. Unl list cannot be empty.\n";
        fields_missing |= cfg.contract.id.empty() && std::cerr << "Missing cfg field: contract id.\n";
        fields_missing |= cfg.mesh.port == 0 && std::cerr << "Missing cfg field: mesh port\n";
        fields_missing |= cfg.user.port == 0 && std::cerr << "Missing cfg field: user port\n";
        fields_missing |= cfg.log.loglevel.empty() && std::cerr << "Missing cfg field: loglevel\n";
        fields_missing |= cfg.log.loggers.empty() && std::cerr << "Missing cfg field: loggers\n";

        if (fields_missing)
        {
            std::cerr << "Required configuration fields missing at " << ctx.config_file << std::endl;
            return -1;
        }

        // Log settings
        const std::unordered_set<std::string> valid_loglevels({"dbg", "inf", "wrn", "err"});
        if (valid_loglevels.count(cfg.log.loglevel) != 1)
        {
            std::cerr << "Invalid loglevel configured. Valid values: dbg|inf|wrn|err\n";
            return -1;
        }

        const std::unordered_set<std::string> valid_loggers({"console", "file"});
        for (const std::string &logger : cfg.log.loggers)
        {
            if (valid_loggers.count(logger) != 1)
            {
                std::cerr << "Invalid logger. Valid values: console|file\n";
                return -1;
            }
        }

        //Sign and verify a sample message to ensure we have a matching signing key pair.
        const std::string msg = "hotpocket";
        const std::string sig = crypto::sign(msg, cfg.node.private_key);
        if (crypto::verify(msg, sig, cfg.node.public_key) != 0)
        {
            std::cerr << "Invalid signing keys. Run with 'rekey' to generate new keys.\n";
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
        const std::string paths[9] = {
            ctx.contract_dir,
            ctx.config_file,
            ctx.hist_dir,
            ctx.full_hist_dir,
            ctx.state_dir,
            ctx.tls_key_file,
            ctx.tls_cert_file,
            ctx.hpfs_exe_path,
            ctx.hpws_exe_path};

        for (const std::string &path : paths)
        {
            if (!util::is_file_exists(path) && !util::is_dir_exists(path))
            {
                if (path == ctx.tls_key_file || path == ctx.tls_cert_file)
                {
                    std::cerr << path << " does not exist. Please provide self-signed certificates. Can generate using command\n"
                              << "openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout tlskey.pem -out tlscert.pem\n"
                              << "and add it to " + ctx.config_dir << std::endl;
                }
                else if (path == ctx.hpfs_exe_path || path == ctx.hpws_exe_path)
                {
                    std::cerr << path << " binary does not exist.\n";
                }
                else
                {
                    std::cerr << path << " does not exist.\n";
                }

                return -1;
            }
        }

        return 0;
    }

    void change_role(const ROLE role)
    {
        // Do not allow to change the mode if the node was started as an observer.
        if (startup_mode == ROLE::OBSERVER || cfg.node.role == role)
            return;

        cfg.node.role = role;

        if (role == ROLE::OBSERVER)
            LOG_INFO << "Switched to OBSERVER mode.";
        else
            LOG_INFO << "Switched back to VALIDATOR mode.";
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

    /**
     * Extracts missing config field from the jsoncons exception message.
     * @param err_message Jsoncons error message.
     * @return Missing config field.
    */
    std::string_view extract_missing_field(std::string err_message)
    {
        err_message.erase(0, err_message.find("'") + 1);
        err_message = err_message.substr(0, err_message.find("'"));
        return err_message;
    }

    /**
     * Update config contract section if a patch file is detected.
     * @param contract_config Contract section of config structure.
     * @return Returns -1 on error and 0 on successful update.
    */
    int apply_patch_changes(contract_params &contract_config)
    {
        pid_t hpfs_ro_pid = 0;
        std::string mount_dir; // Holds the mount directory of the newly created hpfs session.
        int res = 0;

        if (hpfs::start_ro_rw_process(hpfs_ro_pid, mount_dir,
                                      true, false, true) == -1 ||                // Creating a hpfs process and then starts a virtual hpfs session.
            validate_and_apply_patch_config(contract_config, mount_dir) == -1 || // Validate content in patch file and update contract section in config.
            hpfs::stop_fs_session(mount_dir) == -1)                              // Stop the created hpfs session.
            res = -1;

        // Created hpfs process should be killed even the patch validation failed.
        if (hpfs_ro_pid > 0 && util::kill_process(hpfs_ro_pid, true) == -1)
            res = -1;
        return res;
    }

    /**
     * Validate and update contract config section if a patch file detected.
     * @param contract_config Contract section of config structure.
     * @param mount_dir hpfs process mount directory path.
     * @return Returns -1 on error and 0 in successful update.
    */
    int validate_and_apply_patch_config(contract_params &contract_config, std::string_view mount_dir)
    {
        const std::string path = std::string(mount_dir).append("/").append(PATCH_FILE_NAME);
        if (util::is_file_exists(path))
        {
            std::ifstream ifs(path);
            jsoncons::ojson contract;
            try
            {
                contract = jsoncons::ojson::parse(ifs, jsoncons::strict_json_parsing());
            }
            catch (const std::exception &e)
            {
                std::cerr << "Invalid patch config file format. " << e.what() << '\n';
                return -1;
            }
            ifs.close();

            try
            {

                contract_config.version = contract["version"].as<std::string>();
                if (contract_config.version.empty())
                {
                    std::cerr << "Patch contract version not specified.\n";
                    return -1;
                }

                contract_config.unl.clear();
                for (auto &nodepk : contract["unl"].array_range())
                {
                    // Convert the public key hex of each node to binary and store it.
                    const std::string bin_pubkey = util::to_bin(nodepk.as<std::string_view>());
                    if (bin_pubkey.empty())
                    {
                        std::cerr << "Error decoding patch file unl list.\n";
                        return -1;
                    }
                    contract_config.unl.emplace(bin_pubkey);
                }
                if (contract_config.unl.empty())
                {
                    std::cerr << "Patch file unl list cannot be empty.\n";
                    return -1;
                }

                contract_config.bin_path = contract["bin_path"].as<std::string>();
                if (contract_config.bin_path.empty())
                {
                    std::cerr << "Patch file binary path cannot be empty.\n";
                }
                contract_config.bin_args = contract["bin_args"].as<std::string>();
                contract_config.roundtime = contract["roundtime"].as<uint16_t>();
                if (contract_config.roundtime == 0)
                {
                    std::cerr << "Patch file round time cannot be zero.\n";
                }

                if (contract["consensus"] != conf::PUBLIC && contract["consensus"] != conf::PRIVATE)
                {
                    std::cerr << "Invalid consensus flag configured in patch file. Valid values: public|private\n";
                    return -1;
                }
                contract_config.is_consensus_public = contract["consensus"] == conf::PUBLIC;

                if (contract["npl"] != conf::PUBLIC && contract["npl"] != conf::PRIVATE)
                {
                    std::cerr << "Invalid npl flag configured in patch file. Valid values: public|private\n";
                    return -1;
                }
                contract_config.is_npl_public = contract["npl"] == conf::PUBLIC;

                if (!contract["appbill"].contains("mode"))
                {
                    std::cerr << "Required contract appbill config field mode missing at patch file.\n";
                    return -1;
                }
                contract_config.appbill.mode = contract["appbill"]["mode"].as<std::string>();
                if (!contract["appbill"].contains("bin_args"))
                {
                    std::cerr << "Required contract appbill config field bin_args missing at patch file.\n";
                    return -1;
                }
                contract_config.appbill.bin_args = contract["appbill"]["bin_args"].as<std::string>();

                // Populate runtime contract execution args.
                contract_config.runtime_binexec_args.clear();
                if (!contract_config.bin_args.empty())
                    util::split_string(contract_config.runtime_binexec_args, contract_config.bin_args, " ");
                contract_config.runtime_binexec_args.insert(contract_config.runtime_binexec_args.begin(), (contract_config.bin_path[0] == '/' ? contract_config.bin_path : util::realpath(conf::ctx.contract_dir + "/bin/" + contract_config.bin_path)));

                // Populate runtime app bill args.
                contract_config.appbill.runtime_args.clear();
                if (!contract_config.appbill.bin_args.empty())
                    util::split_string(contract_config.appbill.runtime_args, contract_config.appbill.bin_args, " ");
                contract_config.appbill.runtime_args.insert(contract_config.appbill.runtime_args.begin(), (contract_config.appbill.mode[0] == '/' ? contract_config.appbill.mode : util::realpath(conf::ctx.contract_dir + "/bin/" + contract_config.appbill.mode)));

                std::cout << "Contract config updated from " << PATCH_FILE_NAME << " file\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "Required contract config field " << extract_missing_field(e.what()) << " missing in patch file.\n";
                return -1;
            }
        }
        return 0;
    }

    /**
     * Locks the config file. If already locked means there's another hpcore instance running in the same directory.
     * If so, log error and return, Otherwise lock the config.
     * @return Returns 0 if lock is successfully aquired, -1 on error.
    */
    int set_config_lock()
    {
        ctx.config_fd = open(ctx.config_file.data(), O_RDWR, 444);
        if (ctx.config_fd == -1)
            return -1;

        if (util::set_lock(ctx.config_fd, ctx.config_lock, true, 0, 0) == -1)
        {
            if (errno == EACCES || errno == EAGAIN)
            {
                std::cerr << "Another hpcore instance is already running in directory " << ctx.contract_dir << "\n";
            }
            // Close fd if lock aquiring failed.
            close(ctx.config_fd);
            return -1;
        }

        return 0;
    }

    /**
     * Releses the config file and closes the opened file descriptor.
     * @return Returns 0 if lock is successfully aquired, -1 on error.
    */
    int release_config_lock()
    {
        const int res = util::release_lock(ctx.config_fd, ctx.config_lock);
        // Close fd in termination.
        close(ctx.config_fd);
        return res;
    }
} // namespace conf
