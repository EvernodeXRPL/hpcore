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

    // The operating mode of the contract node.
    enum OPERATING_MODE
    {
        OBSERVER = 0, // Observer mode. Only emits NUPs. Does not participate in voting.
        PROPOSER = 1  // Consensus participant mode.
    };

    // Log severity levels used in Hot Pocket.
    enum LOG_SEVERITY
    {
        DEBUG,
        INFO,
        WARN,
        ERROR
    };

    // Holds contextual information about the currently loaded contract.
    struct contract_ctx
    {
        std::string command;       // The CLI command issued to launch HotPocket
        std::string exe_dir;       // Hot Pocket executable dir.
        std::string hpws_exe_path; // hpws executable file path.
        std::string hpfs_exe_path; // hpfs executable file path.

        std::string contract_dir;    // Contract base directory full path
        std::string full_hist_dir;   // Contract full history dir full path
        std::string hist_dir;        // Contract ledger history dir full path
        std::string state_dir;       // Contract state maintenence path (hpfs path)
        std::string state_rw_dir;    // Contract executation read/write state path.
        std::string state_serve_dir; // State server hpfs mount path.
        std::string log_dir;         // Contract log dir full path
        std::string config_dir;      // Contract config dir full path
        std::string config_file;     // Full path to the contract config file
        std::string tls_key_file;    // Full path to the tls secret key file
        std::string tls_cert_file;   // Full path to the tls certificate
    };

    // Holds all the contract config values.
    struct contract_config
    {
        // Config elements which are initialized in memory (these are not directly loaded from the config file)
        std::string pubkey;                            // Contract public key bytes
        std::string seckey;                            // Contract secret key bytes
        std::vector<std::string> runtime_binexec_args; // Contract binary execution args used during runtime.
        std::vector<std::string> runtime_appbill_args; // Appbill execution args used during runtime.

        // Config elements which are loaded from the config file.
        std::string contractid;                                   // Contract guid.
        OPERATING_MODE operating_mode = OPERATING_MODE::OBSERVER; // Configured startup operating mode of the contract (Observer/Proposer).
        std::string pubkeyhex;                                    // Contract hex public key
        std::string seckeyhex;                                    // Contract hex secret key
        std::string binary;                                       // Full path to the contract binary
        std::string binargs;                                      // CLI arguments to pass to the contract binary
        std::string appbill;                                      // binary to execute for appbill
        std::string appbillargs;                                  // any arguments to supply to appbill binary by default
        std::vector<peer_properties> peers;                       // Vector of peers with ip_port, timestamp, capacity
        std::set<std::string> unl;                                // Unique node list (list of binary public keys)
        uint16_t peerport = 0;                                    // Listening port for peer connections
        uint16_t roundtime = 0;                                   // Consensus round time in ms
        uint16_t pubport = 0;                                     // Listening port for public user connections
        uint16_t peerdiscoverytime = 0;                           // Time interval in ms to find for peers dynamicpeerdiscovery should be on for this

        uint16_t peeridletimeout = 0; // Idle connection timeout for peer connections in seconds.
        uint16_t pubidletimeout = 0;  // Idle connection timeout for user connections in seconds.

        uint64_t pubmaxsize = 0;   // User message max size in bytes
        uint64_t pubmaxcpm = 0;    // User message rate (characters(bytes) per minute)
        uint64_t pubmaxbadmpm = 0; // User bad messages per minute
        uint16_t pubmaxcons = 0;   // Max inbound user connections

        uint64_t peermaxsize = 0;      // Peer message max size in bytes
        uint64_t peermaxcpm = 0;       // Peer message rate (characters(bytes) per minute)
        uint64_t peermaxdupmpm = 0;    // Peer max duplicate messages per minute
        uint64_t peermaxbadmpm = 0;    // Peer bad messages per minute
        uint64_t peermaxbadsigpm = 0;  // Peer bad signatures per minute
        uint16_t peermaxcons = 0;      // Max peer connections
        uint16_t peermaxknowncons = 0; // Max known peer connections

        bool is_consensus_public = false; // If true, consensus are broadcasted to non-unl nodes as well.
        bool is_npl_public = false;       // If true, npl messages are broadcasted to non-unl nodes as well.

        bool msgforwarding = false;        // Whether peer message forwarding is on/off.
        bool dynamicpeerdiscovery = false; // Whether dynamic peer discovery is on/off.
        bool fullhistory = false;          // Whether full history mode is on/off.

        std::string loglevel;                    // Log severity level (debug, info, warn, error)
        LOG_SEVERITY loglevel_type;              // Log severity level enum (debug, info, warn, error)
        std::unordered_set<std::string> loggers; // List of enabled loggers (console, file)
    };

    // Global contract context struct exposed to the application.
    // Other modeuls will access context values via this.
    extern contract_ctx ctx;

    // Global configuration struct exposed to the application.
    // Other modeuls will access config values via this.
    extern contract_config cfg;

    int init();

    int rekey();

    int create_contract();

    void set_contract_dir_paths(std::string exepath, std::string basedir);

    int persist_unl_update(const std::set<std::string> &updated_unl);

    //------Internal-use functions for this namespace.

    int read_config(contract_config &cfg);

    int write_config(const contract_config &cfg);

    int populate_runtime_config(contract_config &parsed_cfg);

    int validate_config(const contract_config &cfg);

    int validate_contract_dir_paths();

    int binpair_to_hex(contract_config &cfg);

    void change_operating_mode(const OPERATING_MODE mode);

    LOG_SEVERITY get_loglevel_type(std::string_view severity);
} // namespace conf

#endif
