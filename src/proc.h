#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <map>
#include "shared.h"

using namespace std;
using namespace shared;

namespace proc
{

struct ContractExecArgs
{
    map<string, ContractUser> &users;
    map<string, PeerNode> &peers;
    uint64_t timestamp;

    ContractExecArgs(map<string, ContractUser> &_users, map<string, PeerNode> &_peers, uint64_t _timestamp)
        : users(_users), peers(_peers)
    {
        timestamp = _timestamp;
    }
};

int exec_contract(ContractExecArgs &args);
bool is_contract_running();

} // namespace proc

#endif