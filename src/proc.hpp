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
    // Map of user I/O buffers (map key: user binary public key).
    // The value is a pair holding consensus-verified input and contract-generated output.
    std::unordered_map<std::string, std::pair<std::string, std::string>> &userbufs;

    // Pair of HP<->SC JSON message buffers (mainly used for control messages).
    // Input buffer for HP->SC messages, Output buffer for SC->HP messages.
    std::pair<std::string, std::string> &hpscbufs;
    
    // Current HotPocket timestamp.
    uint64_t timestamp;

    ContractExecArgs(
        uint64_t _timestamp,
        std::unordered_map<std::string, std::pair<std::string, std::string>> &_userbufs,
        std::pair<std::string, std::string> &_hpscbufs) :
            userbufs(_userbufs),
            hpscbufs(_hpscbufs)
    {
        timestamp = _timestamp;
    }
};

int exec_contract(const ContractExecArgs &args);

int await_contract_execution();

//------Internal-use functions for this namespace.

int write_contract_args(const ContractExecArgs &args);

int write_contract_hp_inputs(const ContractExecArgs &args);

int write_contract_user_inputs(const ContractExecArgs &args);

int read_contract_hp_outputs(const ContractExecArgs &args);

int read_contract_user_outputs(const ContractExecArgs &args);

void cleanup_userfds();

int create_and_write_iopipes(std::vector<int> &fds, std::string &inputbuffer);

int read_iopipe(std::vector<int> &fds, std::string &outputbuffer);

void close_unused_fds(bool is_hp);

void close_unused_vectorfds(bool is_hp, std::vector<int> &fds);

} // namespace proc

#endif