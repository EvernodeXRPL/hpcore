#ifndef _HP_PROC_
#define _HP_PROC_

#include "pchheader.hpp"
#include "usr/usr.hpp"
#include "hpfs/h32.hpp"
#include "util.hpp"

/**
 * Contains helper functions regarding POSIX process execution and IPC between HP and SC.
 */
namespace proc
{

/**
 * Represents list of inputs to the contract and the accumulated contract output for those inputs.
 */
struct contract_iobuf_pair
{
    // List of inputs to be fed into the contract.
    std::list<std::string> inputs;

    // Output emitted by contract after execution.
    // (Because we are reading output at the end, there's no way to
    // get a "list" of outputs. So it's always a one contiguous output.)
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
struct contract_exec_args
{
    // Map of user I/O buffers (map key: user binary public key).
    // The value is a pair holding consensus-verified inputs and contract-generated outputs.
    contract_bufmap_t &userbufs;

    // Pair of NPL<->SC byte array message buffers.
    // Input buffers for NPL->SC messages, Output buffers for SC->NPL messages.
    contract_iobuf_pair &nplbuff;

    // Pair of HP<->SC JSON message buffers (mainly used for control messages).
    // Input buffers for HP->SC messages, Output buffers for SC->HP messages.
    contract_iobuf_pair &hpscbufs;
    
    // Current HotPocket timestamp.
    const int64_t timestamp;

    contract_exec_args(
        int64_t timestamp,
        contract_bufmap_t &userbufs,
        contract_iobuf_pair &nplbuff,
        contract_iobuf_pair &hpscbufs) :
            userbufs(userbufs),
            nplbuff(nplbuff),
            hpscbufs(hpscbufs),
            timestamp(timestamp)
    {
    }
};

int exec_contract(const contract_exec_args &args, hpfs::h32 &state_hash);

void deinit();

//------Internal-use functions for this namespace.

int await_process_execution(pid_t pid);

int start_hpfs_rw_session();

int stop_hpfs_rw_session(hpfs::h32 &state_hash);

int write_contract_args(const contract_exec_args &args);

int feed_inputs(const contract_exec_args &args);

int fetch_outputs(const contract_exec_args &args);

int write_contract_hp_npl_inputs(const contract_exec_args &args);

int read_contract_hp_npl_outputs(const contract_exec_args &args);

// Common helper functions

void fdmap_json_to_stream(const contract_fdmap_t &fdmap, std::ostringstream &os);

int create_iopipes_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

int write_contract_fdmap_inputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

void cleanup_fdmap(contract_fdmap_t &fdmap);

int create_iopipes(std::vector<int> &fds);

int write_iopipe(std::vector<int> &fds, std::list<std::string> &inputs);

int write_npl_iopipe(std::vector<int> &fds, std::list<std::string> &inputs);

int read_iopipe(std::vector<int> &fds, std::string &output);

void close_unused_fds(const bool is_hp);

void close_unused_vectorfds(const bool is_hp, std::vector<int> &fds);

} // namespace proc

#endif