#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <iostream>
#include <unordered_map>
#include <vector>
#include "usr/usr.hpp"
#include "util.hpp"

/**
 * Contains helper functions regarding POSIX process execution and IPC between HP and SC.
 */
namespace proc
{

// Common typedef for a map of pubkey->fdlist.
// This is used to keep track of fdlist quadruplet with a public key (eg. user, npl).
typedef std::unordered_map<std::string, std::vector<int>> contract_fdmap;

// Common typedef for a map of pubkey->buf-pair (input buffer and output buffer).
// This is used to keep track of input/output buffer pair with a public key (eg. user, npl)
typedef std::unordered_map<std::string, std::pair<std::string, std::string>> contract_bufmap;

/**
 * Holds information that should be passed into the contract process.
 */
struct ContractExecArgs
{
    // Map of user I/O buffers (map key: user binary public key).
    // The value is a pair holding consensus-verified input and contract-generated output.
    contract_bufmap &userbufs;

    // Map of NPL I/O buffers (map key: Peer binary public key).
    // The value is a pair holding NPL input and contract-generated output.
    contract_bufmap &nplbufs;

    // Pair of HP<->SC JSON message buffers (mainly used for control messages).
    // Input buffer for HP->SC messages, Output buffer for SC->HP messages.
    std::pair<std::string, std::string> &hpscbufs;
    
    // Current HotPocket timestamp.
    uint64_t timestamp;

    ContractExecArgs(
        uint64_t _timestamp,
        contract_bufmap &_userbufs,
        contract_bufmap &_nplbufs,
        std::pair<std::string, std::string> &_hpscbufs) :
            userbufs(_userbufs),
            nplbufs(_nplbufs),
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

int read_contract_hp_outputs(const ContractExecArgs &args);

// Common helper functions

void fdmap_json_to_stream(const contract_fdmap &fdmap, std::ostringstream &os);

int write_contract_fdmap_inputs(contract_fdmap &fdmap, contract_bufmap &bufmap);

int read_contract_fdmap_outputs(contract_fdmap &fdmap, contract_bufmap &bufmap);

void cleanup_fdmap(contract_fdmap &fdmap);

int create_and_write_iopipes(std::vector<int> &fds, std::string &inputbuffer);

int read_iopipe(std::vector<int> &fds, std::string &outputbuffer);

void close_unused_fds(bool is_hp);

void close_unused_vectorfds(bool is_hp, std::vector<int> &fds);

} // namespace proc

#endif