#ifndef _HP_CONF_H_
#define _HP_CONF_H_

#include "lib/rapidjson/document.h"
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
    string pubkeyb64;
    string seckeyb64;
    unsigned char* pubkey;
    unsigned char* seckey;
    string binary;
    string binargs;
    string listenip;
    vector<string> peers;
    vector<string> unl;
    int peerport;
    int roundtime;
    int pubport;
    int pubmaxsize;
    int pubmaxcpm;
};

extern ContractCtx ctx;
extern ContractConfig cfg;
int init(int argc, char **argv);
void load_config();
void save_config();

} // namespace conf

#endif