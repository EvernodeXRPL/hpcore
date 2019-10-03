#ifndef _HP_CONF_H_
#define _HP_CONF_H_

//Hot Pocket version. Displayed on 'hotpocket version' and written to new contract configs.
#define _HP_VERSION_ "0.1"
//minimum compatible contract config version (this will be used to validate contract configs)
#define _HP_MIN_CONTRACT_VERSION_ "0.1"
//minimum compatible peer message version (this will be used to accept/reject incoming peer connections)
//(Keeping this as int for effcient msg payload and comparison)
#define _HP_MIN_PEERMSG_VERSION_ 1

#include <rapidjson/document.h>
#include <vector>

using namespace std;
using namespace rapidjson;

namespace conf
{

struct ContractCtx
{
    string command;
    string contractDir;
    string histDir;
    string stateDir;
    string binDir;
    string configDir;
    string configFile;
};

struct ContractConfig
{
    /*
    Config elements which are only initialized in memory (these are not loaded from the config file)
    */
    //public key bytes
    unsigned char *pubkey;
    //secret key bytes
    unsigned char *seckey;

    /*
    Config elements which are loaded from the config file.
    */
    string pubkeyb64;
    string seckeyb64;
    string binary;
    string binargs;
    string listenip;
    vector<string> peers;
    vector<string> unl;
    unsigned short peerport;
    int roundtime;
    unsigned short pubport;
    int pubmaxsize;
    int pubmaxcpm;
};

extern ContractCtx ctx;
extern ContractConfig cfg;
int init(int argc, char **argv);
void set_contract_dir_paths(string basedir);
void save_config();

} // namespace conf

#endif