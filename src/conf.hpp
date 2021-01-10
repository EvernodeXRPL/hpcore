#ifndef _HP_CONF_
#define _HP_CONF_

#include "pchheader.hpp"

/**
 * Manages the central contract config and context structs.
 * Contains functions to contract config operations such as create/rekey/load.
 */
namespace conf
{
    // Struct to represent ip and port of the peer.
    struct ip_port_prop
    {
        std::string host_address;
        uint16_t port;

        bool operator==(ip_port_prop ip_port)
        {
            return host_address == ip_port.host_address && port == ip_port.port;
        }

        bool operator!=(ip_port_prop ip_port)
        {
            return !(host_address == ip_port.host_address && port == ip_port.port);
        }
    };

    // Struct to represent information about a peer.
    // Initially available capacity is set to -1 and timestamp is set to 0.
    // Later it will be updated according to the capacity anouncement from the peers.
    struct peer_properties
    {
        ip_port_prop ip_port;
        int16_t available_capacity = -1;
        uint64_t timestamp = 0;
    };

    // The role of the contract node.
    enum ROLE
    {
        OBSERVER = 0, // Observer mode. Only emits NUPs. Does not participate in voting.
        VALIDATOR = 1 // Consensus participant mode.
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
        std::string loglevel;                    // Log severity level (debug, info, warn, error)
        LOG_SEVERITY loglevel_type;              // Log severity level enum (debug, info, warn, error)
        std::unordered_set<std::string> loggers; // List of enabled loggers (console, file)
    };

    struct node_config
    {
        // Config elements which are initialized in memory (these are not directly loaded from the config file)
        std::string public_key;     // Contract public key bytes
        std::string private_key;    // Contract private key bytes
        ROLE role = ROLE::OBSERVER; // Configured startup role of the contract (Observer/validator).
        bool is_unl = false;        // Indicate whether we are a unl node or not.

        std::string public_key_hex;  // Contract hex public key
        std::string private_key_hex; // Contract hex private key
        bool full_history = false;   // Whether full history mode is on/off.
    };

    struct appbill_config
    {
        std::string mode;     // Binary to execute for appbill.
        std::string bin_args; // Any arguments to supply to appbill binary by default.

        // Config element which are initialized in memory (This is not directly loaded from the config file)
        std::vector<std::string> runtime_args; // Appbill execution args used during runtime.
    };
    struct contract_params
    {
        std::string id;                   // Contract guid.
        std::string version;              // Contract version string.
        std::set<std::string> unl;        // Unique node list (list of binary public keys)
        std::string bin_path;             // Full path to the contract binary
        std::string bin_args;             // CLI arguments to pass to the contract binary
        uint16_t roundtime = 0;           // Consensus round time in ms
        bool is_consensus_public = false; // If true, consensus are broadcasted to non-unl nodes as well.
        bool is_npl_public = false;       // If true, npl messages are broadcasted to non-unl nodes as well.
        appbill_config appbill;

        // Config element which are initialized in memory (This is not directly loaded from the config file)
        std::vector<std::string> runtime_binexec_args; // Contract binary execution args used during runtime.
    };

    struct user_config
    {
        uint16_t port = 0;                 // Listening port for public user connections
        uint16_t idle_timeout = 0;         // Idle connection timeout for user connections in seconds.
        uint64_t max_bytes_per_msg = 0;    // User message max size in bytes
        uint64_t max_bytes_per_min = 0;    // User message rate (characters(bytes) per minute)
        uint64_t max_bad_msgs_per_min = 0; // User bad messages per minute
        uint16_t max_connections = 0;      // Max inbound user connections
        bool enabled = true;               // User connections enable/disable.
    };

    struct peer_discovery_config
    {
        bool enabled = false;  // Whether dynamic peer discovery is on/off.
        uint16_t interval = 0; // Time interval in ms to find for peers dynamicpeerdiscovery should be on for this
    };

    struct mesh_config
    {
        uint16_t port = 0;                        // Listening port for peer connections
        std::vector<peer_properties> known_peers; // Vector of peers with ip_port, timestamp, capacity
        bool msg_forwarding = false;              // Whether peer message forwarding is on/off.
        uint16_t max_connections = 0;             // Max peer connections
        uint16_t max_known_connections = 0;       // Max known peer connections
        uint64_t max_bytes_per_msg = 0;           // Peer message max size in bytes
        uint64_t max_bytes_per_min = 0;           // Peer message rate (characters(bytes) per minute)
        uint64_t max_bad_msgs_per_min = 0;        // Peer bad messages per minute
        uint64_t max_bad_msgsigs_per_min = 0;     // Peer bad signatures per minute
        uint64_t max_dup_msgs_per_min = 0;        // Peer max duplicate messages per minute
        uint16_t idle_timeout = 0;                // Idle connection timeout for peer connections in seconds.
        peer_discovery_config peer_discovery;     // Peer discovery configs.
    };

    // Holds contextual information about the currently loaded contract.
    struct contract_ctx
    {
        std::string command;       // The CLI command issued to launch HotPocket
        std::string exe_dir;       // Hot Pocket executable dir.
        std::string hpws_exe_path; // hpws executable file path.
        std::string hpfs_exe_path; // hpfs executable file path.

        std::string contract_dir;   // Contract base directory full path.
        std::string full_hist_dir;  // Contract full history dir full path.
        std::string hist_dir;       // Contract ledger history dir full path.
        std::string hpfs_dir;       // hpfs metdata dir (The location of hpfs log file).
        std::string hpfs_mount_dir; // hpfs fuse file system mount path.
        std::string hpfs_rw_dir;    // hpfs read/write fs session path.
        std::string log_dir;        // Contract log dir full path.
        std::string config_dir;     // Contract config dir full path.
        std::string config_file;    // Full path to the contract config file.
        std::string tls_key_file;   // Full path to the tls private key file.
        std::string tls_cert_file;  // Full path to the tls certificate.

        int config_fd;            // Config file file descriptor.
        struct flock config_lock; // Config file lock.
    };

    // Holds all the contract config values.
    struct contract_config
    {
        // Config elements which are loaded from the config file.
        std::string hp_version; // Version of Hot Pocket that generated the config.
        node_config node;
        contract_params contract;
        mesh_config mesh;
        user_config user;
        log_config log;
    };

    // Global contract context struct exposed to the application.
    // Other modeuls will access context values via this.
    extern contract_ctx ctx;

    // Global configuration struct exposed to the application.
    // Other modeuls will access config values via this.
    extern contract_config cfg;

    int init();

    void deinit();

    int rekey();

    int create_contract();

    void set_contract_dir_paths(std::string exepath, std::string basedir);

    //------Internal-use functions for this namespace.

    int read_config(contract_config &cfg);

    int write_config(const contract_config &cfg);

    int validate_config(const contract_config &cfg);

    int validate_contract_dir_paths();

    void change_role(const ROLE role);

    LOG_SEVERITY get_loglevel_type(std::string_view severity);

    const std::string extract_missing_field(std::string err_message);

    int populate_patch_config();

    int apply_patch_config(std::string_view hpfs_session_name);

    int set_config_lock();

    int release_config_lock();

    void populate_contract_section_json(jsoncons::ojson &jdoc, const contract_params &contract, const bool include_id);

    int parse_contract_section_json(contract_params &contract, const jsoncons::ojson &json, const bool parse_id);

    int write_json_file(const std::string &file_path, const jsoncons::ojson &d);

} // namespace conf

#endif
