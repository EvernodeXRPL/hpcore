#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <map>
#include "usr/usr.hpp"
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
    uint64_t timestamp; // Current HotPocket timestamp.

    ContractExecArgs(uint64_t _timestamp)
    {
        timestamp = _timestamp;
    }
};

int exec_contract(const ContractExecArgs &args);

bool is_contract_running();

//------Internal-use functions for this namespace.

int create_userpipes();

int write_to_stdin(const ContractExecArgs &args);

void close_unused_userfds(bool is_hp);

void cleanup_userfds(const usr::contract_user &user);

void write_contract_user_inputs();

int read_contract_user_outputs();

} // namespace proc

#endif