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

// Holds contextual information about the currently loaded contract.
struct contract_ctx
{
    std::string command; // The CLI command issued to launch HotPocket

    std::string contractDir; // Contract base directory
    std::string histDir;     // Contract history dir
    std::string stateDir;    // Contract state dir
    std::string stateMapDir;    // Contract state map dir (.merkel files)
    std::string logDir;      // Contract log dir
    std::string configDir;   // Contract config dir
    std::string configFile;  // Full path to the contract config file
    std::string tlsKeyFile;     // Full path to the tls secret key file
    std::string tlsCertFile; // Full path to the tls certificate
};

// Holds all the contract config values.
struct contract_config
{
    // Config elements which are initialized in memory (these are not directly loaded from the config file)

    std::string pubkey; // Contract public key bytes
    std::string seckey; // Contract secret key bytes

    // Config elements which are loaded from the config file.

    std::string pubkeyhex;                                  // Contract hex public key
    std::string seckeyhex;                                  // Contract hex secret key
    std::string keytype;                                    // Key generation algorithm used by libsodium
    std::string binary;                                     // Full path to the contract binary
    std::string binargs;                                    // CLI arguments to pass to the contract binary
    std::string listenip;                                   // The IPs to listen on for incoming connections
    std::unordered_map<std::string, ip_port_pair> peers;    // Map of peers keyed by "<ip address>:<port>" concatenated format
    std::unordered_set<std::string> unl;                    // Unique node list (list of binary public keys)
    uint16_t peerport;                                      // Listening port for peer connections
    uint16_t roundtime;                                     // Consensus round time in ms
    uint16_t pubport;                                       // Listening port for public user connections
    
    uint64_t pubmaxsize;                                    // User message max size in bytes
    uint64_t pubmaxcpm;                                     // User message rate (characters(bytes) per minute)
    uint64_t pubmaxbadmpm;                                  // User bad messages per minute
    
    uint64_t peermaxsize;                                   // Peer message max size in bytes
    uint64_t peermaxcpm;                                    // Peer message rate (characters(bytes) per minute)
    uint64_t peermaxdupmpm;                                 // Peer max duplicate messages per minute
    uint64_t peermaxbadmpm;                                 // Peer bad messages per minute
    uint64_t peermaxbadsigpm;                               // Peer bad signatures per minute

    std::string loglevel;                                   // Log severity level (debug, info, warn, error)
    std::unordered_set<std::string> loggers;                // List of enabled loggers (console, file)
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

void set_contract_dir_paths(std::string basedir);

//------Internal-use functions for this namespace.

int load_config();

int save_config();

int validate_config();

int validate_contract_dir_paths();

int is_schema_valid(const rapidjson::Document &d);

int binpair_to_hex();

int hexpair_to_bin();

} // namespace conf

#endif