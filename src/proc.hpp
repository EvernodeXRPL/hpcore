#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <map>
#include "util.hpp"

using namespace std;
using namespace util;

namespace proc
{

/**
 * Holds information that should be passed into the contract process.
 */
struct ContractExecArgs
{
    map<string, contract_user> &users;      // Map of authenticated contract users indexed by user pubkey.
    map<string, peer_node> &peers;          // Map of connected peers indexed by node pubkey.
    uint64_t timestamp;                     // Current HotPocket timestamp.

    ContractExecArgs(map<string, contract_user> &_users, map<string, peer_node> &_peers, uint64_t _timestamp)
        : users(_users), peers(_peers)
    {
        timestamp = _timestamp;
    }
};

/**
 * Executes the contract process and passes the specified arguments.
 * 
 * @return 0 on successful process creation. -1 on failure or contract process is already running.
 */
int exec_contract(ContractExecArgs &args);

/**
 * Checks whether the contract process is running at this moment.
 */
bool is_contract_running();

} // namespace proc

#endif