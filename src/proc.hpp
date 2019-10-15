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
    // Map of user I/O buffers (map key: user public key).
    // The value is a pair holding consensus-verified input and contract-generated output.
    std::unordered_map<std::string, std::pair<std::string, std::string>> &userbufs;
    
    // Current HotPocket timestamp.
    uint64_t timestamp;

    ContractExecArgs(
        uint64_t _timestamp,
        std::unordered_map<std::string, std::pair<std::string, std::string>> &_userbufs) :
            userbufs(_userbufs)
    {
        timestamp = _timestamp;
    }
};

int exec_contract(const ContractExecArgs &args);

//------Internal-use functions for this namespace.

int write_to_stdin(const ContractExecArgs &args);

int write_verified_user_inputs(const ContractExecArgs &args);

int read_contract_user_outputs(const ContractExecArgs &args);

void close_unused_userfds(bool is_hp);

void cleanup_userfds();

} // namespace proc

#endif