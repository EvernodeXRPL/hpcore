#ifndef _HP_PROC_
#define _HP_PROC_

#include "pchheader.hpp"
#include "usr/usr.hpp"
#include "util.hpp"

/**
 * Contains helper functions regarding POSIX process execution and IPC between HP and SC.
 */
namespace proc
{

/**
 * Represents list of inputs to the contract and the accumilated contract output for those inputs.
 */
struct contract_iobuf_pair
{
    // List of inputs to be fed into the contract.
    std::list<std::string> inputs;

    // Output emitted by contract after execution. (Because we are reading output at the end, there's no way to
    // get a "list" of outputs. So it's always a one contingous output.)
    std::string output;    
};

// Common typedef for a map of pubkey->fdlist.
// This is used to keep track of fdlist quadruplet with a public key (eg. user, npl).
typedef std::unordered_map<std::string, std::vector<int>> contract_fdmap_t;

// Common typedef for a map of pubkey->I/O list pair (input list and output list).
// This is used to keep track of input/output buffers for a given public key (eg. user, npl)
typedef std::unordered_map<std::string, contract_iobuf_pair> contract_bufmap_t;

/**
 * Holds information that should be passed into the contract process.
 */
struct ContractExecArgs
{
    // Map of user I/O buffers (map key: user binary public key).
    // The value is a pair holding consensus-verified inputs and contract-generated outputs.
    contract_bufmap_t &userbufs;

    // Map of NPL I/O buffers (map key: Peer binary public key).
    // The value is a pair holding NPL inputs and contract-generated outputs.
    contract_bufmap_t &nplbufs;

    // Pair of HP<->SC JSON message buffers (mainly used for control messages).
    // Input buffers for HP->SC messages, Output buffers for SC->HP messages.
    contract_iobuf_pair &hpscbufs;
    
    // Current HotPocket timestamp.
    int64_t timestamp;

    ContractExecArgs(
        int64_t _timestamp,
        contract_bufmap_t &_userbufs,
        contract_bufmap_t &_nplbufs,
        contract_iobuf_pair &_hpscbufs) :
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

void fdmap_json_to_stream(const contract_fdmap_t &fdmap, std::ostringstream &os);

int write_contract_fdmap_inputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

void cleanup_fdmap(contract_fdmap_t &fdmap);

int create_and_write_iopipes(std::vector<int> &fds, std::list<std::string> &inputs);

int read_iopipe(std::vector<int> &fds, std::string &output);

void close_unused_fds(bool is_hp);

void close_unused_vectorfds(bool is_hp, std::vector<int> &fds);

} // namespace proc

#endif