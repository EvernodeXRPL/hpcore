#ifndef _HP_CONF_H_
#define _HP_CONF_H_

#include <rapidjson/document.h>
#include <vector>

using namespace std;
using namespace rapidjson;

namespace conf
{

// Holds contextual information of the currently loaded contract.
struct contract_ctx
{

    string command; // The CLI command issued to launch HotPocket

    string contractDir; // Contract base directory
    string histDir;     // Contract history dir
    string stateDir;    // Contract state dir
    string configDir;   // Contract config dir
    string configFile;  // Full path to the contract config file
};

//
struct contract_config
{
    // Config elements which are initialized in memory (these are not directly loaded from the config file)

    string pubkey;              // Contract public key bytes
    string seckey;              // Contract secret key bytes


    // Config elements which are loaded from the config file.

    string pubkeyb64;           // Contract base64 public key
    string seckeyb64;           // Contract base64 secret key
    string binary;              // Full path to the contract binary
    string binargs;             // CLI arguments to pass to the contract binary
    string listenip;            // The IPs to listen on for incoming connections
    vector<string> peers;       // List of peers in the format "<ip address>:<port>"
    vector<string> unl;         // Unique node list (list of base64 public keys)
    unsigned short peerport;    // Listening port for peer connections
    int roundtime;              // Consensus round time in ms
    unsigned short pubport;     // Listening port for public user connections
    int pubmaxsize;             // User message max size in bytes
    int pubmaxcpm;              // User message rate
};

//Global contract context struct exposed to the application.
extern contract_ctx ctx;

//Global configuration struct exposed to the application.
extern contract_config cfg;

/**
 * Loads and initializes the contract config for execution. Must be called once during application startup.
 * @return 0 for success. -1 for failure.
 */
int init();

/**
 * Generates and saves new signing keys in the contract config.
 */
int rekey();

/**
 * Creates a new contract directory with the default contract config.
 */
int create_contract();

/**
 * Updates the contract context with directory paths based on provided base directory.
 */
void set_contract_dir_paths(string basedir);

} // namespace conf

#endif