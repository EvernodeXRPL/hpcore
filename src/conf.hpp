#ifndef _HP_CONF_
#define _HP_CONF_

#include "pchheader.hpp"
#include "util/util.hpp"

/**
 * Manages the central config and context structs.
 * Contains functions to config operations such as create/rekey/load.
 */
namespace conf
{
    constexpr size_t CONCURRENT_READ_REQUEST_MAX_LIMIT = 32;

#define CURRENT_TIME_CONFIG ((conf::cfg.contract.roundtime * 100) + conf::cfg.contract.stage_slice)

    // Struct to represent ip and port of the peer.
    struct peer_ip_port
    {
        std::string host_address;
        uint16_t port = 0;

        bool operator==(const peer_ip_port &other) const
        {
            return host_address == other.host_address && port == other.port;
        }

        bool operator!=(const peer_ip_port &other) const
        {
            return !(host_address == other.host_address && port == other.port);
        }

        bool operator<(const peer_ip_port &other) const
        {
            return (host_address == other.host_address) ? port < other.port : host_address < other.host_address;
        }

        const std::string to_string() const
        {
            return host_address + ":" + std::to_string(port);
        }
    };

    struct ugid
    {
        uid_t uid = 0;
        gid_t gid = 0;

        bool empty() const
        {
            return uid <= 0 && gid <= 0;
        }

        int from_string(std::string_view str)
        {
            if (str.empty())
                return 0;

            std::vector<std::string> ids;
            util::split_string(ids, str, ":");
            if (ids.size() == 2)
            {
                const int _uid = atoi(ids[0].c_str());
                const int _gid = atoi(ids[1].c_str());

                if (_uid > 0 && _gid > 0)
                {
                    uid = _uid;
                    gid = _gid;
                    return 0;
                }
            }

            return -1;
        }

        const std::string to_string() const
        {
            return (uid == 0 && gid == 0) ? "" : (std::to_string(uid) + ":" + std::to_string(gid));
        }
    };

    // The role of the contract node.
    enum ROLE
    {
        OBSERVER = 0, // Observer mode. Only emits NUPs. Does not participate in voting.
        VALIDATOR = 1 // Consensus participant mode.
    };

    // History modes of the node.
    enum HISTORY
    {
        FULL, // Full history mode.
        CUSTOM
    };

    // Max number of shards to keep for primary and raw shards.
    struct history_configuration
    {
        uint64_t max_primary_shards = 0; // Maximum number of shards for primary shards.
        uint64_t max_raw_shards = 0;     // Maximum number of shards for raw data shards.
    };

    struct node_config
    {
        // Config elements which are initialized in memory (these are not directly loaded from the config file)
        std::string public_key;     // Contract public key bytes
        std::string private_key;    // Contract private key bytes
        ROLE role = ROLE::OBSERVER; // Configured startup role of the contract (Observer/validator).
        bool is_unl = false;        // Indicate whether we are a unl node or not.

        std::string public_key_hex;           // Contract hex public key
        std::string private_key_hex;          // Contract hex private key
        HISTORY history;                      // Node is a full history node if history=full.
        history_configuration history_config; // Holds history config values. Only applicable if history=custom.
    };

    struct appbill_config
    {
        std::string mode;     // Binary to execute for appbill.
        std::string bin_args; // Any arguments to supply to appbill binary by default.

        // Config element which are initialized in memory (This is not directly loaded from the config file)
        std::vector<std::string> runtime_args; // Appbill execution args used during runtime.
    };

    struct round_limits_config
    {
        size_t user_input_bytes = 0;  // Max contract input bytes per user per round.
        size_t user_output_bytes = 0; // Max contract output bytes per user per round.
        size_t npl_output_bytes = 0;  // Max npl output bytes per round.
        size_t proc_cpu_seconds = 0;  // Max CPU time the contract process can consume.
        size_t proc_mem_bytes = 0;    // Max memory the contract process can allocate.
        size_t proc_ofd_count = 0;    // Max no. of open file descriptors the contract process can allocate.
    };

    struct contract_log_config
    {
        bool enable = false;            // Whether to log stdout/err of the contract process.
        size_t max_mbytes_per_file = 0; // Max MB size of a single log file.
        size_t max_file_count = 0;      // Max no. of log files to keep.
    };

    struct contract_config
    {
        std::string id;          // Contract guid.
        bool execute = false;    // Whether or not to execute the contract on the node.
        ugid run_as;             // The user/groups id to execute the contract as.
        contract_log_config log; // Contract log related settings.

        std::string version;                   // Contract version string.
        std::set<std::string> unl;             // Unique node list (list of binary public keys).
        std::string bin_path;                  // Full path to the contract binary.
        std::string bin_args;                  // CLI arguments to pass to the contract binary.
        std::atomic<uint32_t> roundtime = 0;   // Consensus round time in ms (max: 3,600,000).
        std::atomic<uint32_t> stage_slice = 0; // Percentage slice of round time that stages 0,1,2 get (max: 33).
        bool is_consensus_public = false;      // If true, consensus are broadcasted to non-unl nodes as well.
        bool is_npl_public = false;            // If true, npl messages are broadcasted to non-unl nodes as well.
        uint16_t max_input_ledger_offset;      // Maximum ledger sequence number offset that can be specified in the input.
        appbill_config appbill;
        round_limits_config round_limits;

        // Config element which are initialized in memory (This is not directly loaded from the config file)
        std::vector<std::string> runtime_binexec_args; // Contract binary execution args used during runtime.
    };

    struct user_config
    {
        uint16_t port = 0;                        // Listening port for public user connections
        bool listen = true;                       // Whether to listen for incoming user connections.
        uint32_t idle_timeout = 0;                // Idle connection timeout ms for user connections.
        uint64_t max_bytes_per_msg = 0;           // User message max size in bytes
        uint64_t max_bytes_per_min = 0;           // User message rate (characters(bytes) per minute)
        uint64_t max_bad_msgs_per_min = 0;        // User bad messages per minute
        uint16_t max_connections = 0;             // Max inbound user connections
        uint16_t max_in_connections_per_host = 0; // Max inbound user connections per remote host (IP).
        uint64_t concurrent_read_requests = 4;    // Supported concurrent read requests count.
    };

    struct peer_discovery_config
    {
        bool enabled = false;  // Whether dynamic peer discovery is on/off.
        uint16_t interval = 0; // Time interval in ms to find for peers dynamicpeerdiscovery should be on for this
    };

    struct mesh_config
    {
        uint16_t port = 0;                        // Listening port for peer connections
        bool listen = true;                       // Whether to listen for incoming peer connections.
        uint32_t idle_timeout = 0;                // Idle connection timeout ms for peer connections.
        std::set<peer_ip_port> known_peers;       // Ordered set of peers with ip_port.
        bool msg_forwarding = false;              // Whether peer message forwarding is on/off.
        uint16_t max_connections = 0;             // Max peer connections.
        uint16_t max_known_connections = 0;       // Max known peer connections.
        uint16_t max_in_connections_per_host = 0; // Max inbound peer connections per remote host (IP).
        uint64_t max_bytes_per_msg = 0;           // Peer message max size in bytes.
        uint64_t max_bytes_per_min = 0;           // Peer message rate (characters(bytes) per minute).
        uint64_t max_bad_msgs_per_min = 0;        // Peer bad messages per minute.
        uint64_t max_bad_msgsigs_per_min = 0;     // Peer bad signatures per minute.
        uint64_t max_dup_msgs_per_min = 0;        // Peer max duplicate messages per minute.
        peer_discovery_config peer_discovery;     // Peer discovery configs.
    };

    struct hpfs_log_config
    {
        std::string log_level; // Log severity level (dbg, inf, wrn, wrr)
    };

    struct hpfs_config
    {
        bool external = false; // Whether to refrain from manageing built-in hpfs process or not.
        hpfs_log_config log;
    };

    // Holds contextual information about the currently loaded contract.
    struct contract_ctx
    {
        std::string command;       // The CLI command issued to launch HotPocket
        std::string exe_dir;       // Hot Pocket executable dir.
        std::string hpws_exe_path; // hpws executable file path.
        std::string hpfs_exe_path; // hpfs executable file path.

        std::string contract_dir;            // Contract base directory full path.
        std::string contract_hpfs_dir;       // Contract hpfs metadata dir (The location of hpfs log file).
        std::string contract_hpfs_mount_dir; // Contract hpfs fuse file system mount path.
        std::string contract_hpfs_rw_dir;    // Contract hpfs read/write fs session path.
        std::string ledger_hpfs_dir;         // Ledger hpfs metadata dir (The location of hpfs log file).
        std::string ledger_hpfs_mount_dir;   // Ledger hpfs fuse file system mount path.
        std::string ledger_hpfs_rw_dir;      // Ledger hpfs read/write fs session path.
        std::string log_dir;                 // HotPocket log dir full path.
        std::string contract_log_dir;        // Contract log dir full path.
        std::string config_dir;              // Config dir full path.
        std::string config_file;             // Full path to the config file.
        std::string tls_key_file;            // Full path to the tls private key file.
        std::string tls_cert_file;           // Full path to the tls certificate.

        int config_fd = -1;       // Config file file descriptor.
        struct flock config_lock; // Config file lock.
    };

    // Log severity levels used in Hot Pocket.
    enum LOG_SEVERITY
    {
        DEBUG,
        INFO,
        WARN,
        ERROR
    };

    struct log_config
    {
        std::string log_level;                   // Log severity level (dbg, inf, wrn, wrr)
        LOG_SEVERITY log_level_type;             // Log severity level enum (debug, info, warn, error)
        std::unordered_set<std::string> loggers; // List of enabled loggers (console, file)
        size_t max_mbytes_per_file = 0;          // Max MB size of a single log file.
        size_t max_file_count = 0;               // Max no. of log files to keep.
    };

    // Holds all the config values.
    struct hp_config
    {
        node_config node;
        contract_config contract;
        mesh_config mesh;
        user_config user;
        hpfs_config hpfs;
        log_config log;
    };

    // Global contract context struct exposed to the application.
    // Other modeuls will access context values via this.
    extern contract_ctx ctx;

    // Global configuration struct exposed to the application.
    // Other modeuls will access config values via this.
    extern hp_config cfg;

    int init();

    void deinit();

    int rekey();

    int create_contract();

    void set_contract_dir_paths(std::string exepath, std::string basedir);

    //------Internal-use functions for this namespace.

    int read_config(hp_config &cfg);

    int write_config(const hp_config &cfg);

    int validate_config(const hp_config &cfg);

    int validate_contract_dir_paths();

    void change_role(const ROLE role);

    LOG_SEVERITY get_loglevel_type(std::string_view severity);

    void print_missing_field_error(std::string_view jpath, const std::exception &e, const bool is_patch_config = false);

    int populate_patch_config();

    int apply_patch_config(std::string_view hpfs_session_name);

    int persist_updated_configs();

    int set_config_lock();

    int release_config_lock();

    void populate_contract_section_json(jsoncons::ojson &jdoc, const contract_config &contract, const bool is_patch_config);

    int parse_contract_section_json(contract_config &contract, const jsoncons::ojson &json, const bool is_patch_config);

    int write_json_file(const std::string &file_path, const jsoncons::ojson &d);

} // namespace conf

#endif
