#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <map>
#include "usr/contract_user.hpp"
#include "util.hpp"

/**
 * Contains helper functions regarding POSIX process execution and IPC between HP and SC.
 */
namespace proc
{

/**
 * Holds information that should be passed into the contract process.
 */
struct ContractExecArgs
{
    std::map<std::string, usr::contract_user> &users; // Map of authenticated contract users indexed by user pubkey.
    std::map<std::string, util::peer_node> &peers;     // Map of connected peers indexed by node pubkey.
    uint64_t timestamp;                // Current HotPocket timestamp.

    ContractExecArgs(std::map<std::string, usr::contract_user> &_users, std::map<std::string, util::peer_node> &_peers, uint64_t _timestamp)
        : users(_users), peers(_peers)
    {
        timestamp = _timestamp;
    }
};

int exec_contract(const ContractExecArgs &args);

bool is_contract_running();

//------Internal-use functions for this namespace.

int write_to_stdin(const ContractExecArgs &args);

} // namespace proc

#endif