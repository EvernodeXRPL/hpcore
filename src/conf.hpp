#ifndef _HP_CONF_
#define _HP_CONF_

#include "pchheader.hpp"

/**
 * Manages the central contract config and context structs.
 * Contains functions to contract config operations such as create/rekey/load.
 */
namespace conf
{

// Typedef to represent ip address and port pair.
typedef std::pair<std::string, std::string> ip_port_pair;

// The operating mode of the contract node.
enum OPERATING_MODE
{
    OBSERVING = 0,    // Observer mode. Only emits NUPs. Does not participate in voting.
    PROPOSING = 1      // Consensus participant mode.
};

// Holds contextual information about the currently loaded contract.
struct contract_ctx
{
    std::string command;        // The CLI command issued to launch HotPocket
    std::string exedir;         // Hot Pocket executable dir.
    std::string statemonexepath;// State monitor executable file path.

    std::string contractdir;    // Contract base directory full path
    std::string histdir;        // Contract history dir full path
    std::string statedir;       // Contract executing state dir full path (This is the fuse mount point)
    std::string statehistdir;   // Contract state history dir full path
    std::string logdir;         // Contract log dir full path
    std::string configdir;      // Contract config dir full path
    std::string configfile;     // Full path to the contract config file
    std::string tlskeyfile;     // Full path to the tls secret key file
    std::string tlscertfile;    // Full path to the tls certificate
};

// Holds all the contract config values.
struct contract_config
{
    // Config elements which are initialized in memory (these are not directly loaded from the config file)

    std::string pubkey;                 // Contract public key bytes
    std::string seckey;                 // Contract secret key bytes
    std::vector<std::string> runtime_binexec_args;   // Contract binary execution args used during runtime.

    // Config elements which are loaded from the config file.

    OPERATING_MODE mode;                // Operating mode of the contract (Passive/Active).
    std::string pubkeyhex;              // Contract hex public key
    std::string seckeyhex;              // Contract hex secret key
    std::string keytype;                // Key generation algorithm used by libsodium
    std::string binary;                 // Full path to the contract binary
    std::string binargs;                // CLI arguments to pass to the contract binary
    std::string listenip;               // The IPs to listen on for incoming connections
    std::unordered_map<std::string, ip_port_pair> peers;    // Map of peers keyed by "<ip address>:<port>" concatenated format
    std::unordered_set<std::string> unl;                    // Unique node list (list of binary public keys)
    uint16_t peerport;                  // Listening port for peer connections
    uint16_t roundtime;                 // Consensus round time in ms
    uint16_t pubport;                   // Listening port for public user connections
    
    uint64_t pubmaxsize;                // User message max size in bytes
    uint64_t pubmaxcpm;                 // User message rate (characters(bytes) per minute)
    uint64_t pubmaxbadmpm;              // User bad messages per minute
    uint16_t pubmaxcons;                // Max inbound user connections
    
    uint64_t peermaxsize;               // Peer message max size in bytes
    uint64_t peermaxcpm;                // Peer message rate (characters(bytes) per minute)
    uint64_t peermaxdupmpm;             // Peer max duplicate messages per minute
    uint64_t peermaxbadmpm;             // Peer bad messages per minute
    uint64_t peermaxbadsigpm;           // Peer bad signatures per minute
    uint16_t peermaxcons;               // Max inbound peer connections

    std::string loglevel;                       // Log severity level (debug, info, warn, error)
    std::unordered_set<std::string> loggers;    // List of enabled loggers (console, file)
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

//------Internal-use functions for this namespace.

int load_config();

int save_config();

int validate_config();

int validate_contract_dir_paths();

int is_schema_valid(const rapidjson::Document &d);

int binpair_to_hex();

int hexpair_to_bin();

void change_operating_mode(const OPERATING_MODE mode);

} // namespace conf

#endif