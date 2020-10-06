#ifndef _HP_SC_
#define _HP_SC_

#include "pchheader.hpp"
#include "usr/usr.hpp"
#include "hpfs/h32.hpp"
#include "util.hpp"
#include "p2p/p2p.hpp"

/**
 * Contains helper functions regarding POSIX process execution and IPC between HP and SC.
 */
namespace sc
{

    // Enum used to differenciate pipe fds maintained for SC I/O pipes.
    enum FDTYPE
    {
        // Used by Smart Contract to read input sent by Hot Pocket.
        SCREAD = 0,
        // Used by Hot Pocket to write input to the smart contract.
        HPWRITE = 1,
        // Used by Hot Pocket to read output from the smart contract.
        HPREAD = 2,
        // Used by Smart Contract to write output back to Hot Pocket.
        SCWRITE = 3
    };

    // Enum used to differenciate socket fds maintained for SC sockets.
    enum SOCKETFDTYPE
    {
        // Used by Smart Contract to read input sent by Hot Pocket.
        // Used by Smart Contract to write output back to Hot Pocket.
        SCREADWRITE = 0,
        // Used by Hot Pocket to write input to the smart contract.
        // Used by Hot Pocket to read output from the smart contract.
        HPREADWRITE = 1
    };

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
    struct contract_execution_args
    {
        // Whether the contract should execute in read only mode (to serve read requests).
        bool readonly = false;

        // State dir path to be used for this execution.
        std::string state_dir;

        // Map of user I/O buffers (map key: user binary public key).
        // The value is a pair holding consensus-verified inputs and contract-generated outputs.
        contract_bufmap_t userbufs;

        // NPL messages to be passed into contract.
        std::list<p2p::npl_message> npl_messages;
        
        // Output NPL buffer.
        std::string npl_output;

        // Pair of HP<->SC JSON message buffers (mainly used for control messages).
        // Input buffers for HP->SC messages, Output buffers for SC->HP messages.
        contract_iobuf_pair hpscbufs;

        // Current HotPocket consensus time.
        int64_t time = 0;

        // Current HotPocket lcl (seq no. and ledger hash hex)
        std::string lcl;

        // State hash after execution will be copied to this (not applicable to read only mode).
        hpfs::h32 post_execution_state_hash = hpfs::h32_empty;
    };

    /**
 * Holds context information relating to contract execution environment.
 */
    struct execution_context
    {
        // The arguments that was used to initiate this execution.
        contract_execution_args args;

        // Map of user pipe fds (map key: user public key)
        contract_fdmap_t userfds;

        // Pipe fds for NPL <--> messages.
        std::vector<int> nplfds;

        // Pipe fds for HP <--> messages.
        std::vector<int> hpscfds;

        // Holds the contract process id (if currently executing).
        pid_t contract_pid = 0;

        // Holds the hpfs rw process id (if currently executing).
        pid_t hpfs_pid = 0;

        // Thread to collect contract outputs while contract is running.
        std::thread output_fetcher_thread;

        // Indicates that the deinit procedure has begun.
        bool should_stop = false;
    };

    int execute_contract(execution_context &ctx);

    //------Internal-use functions for this namespace.

    int await_process_execution(pid_t pid);

    int start_hpfs_rw_session(execution_context &ctx);

    int stop_hpfs_rw_session(execution_context &ctx);

    int write_contract_args(const execution_context &ctx);

    int feed_inputs(execution_context &ctx);

    int fetch_outputs(execution_context &ctx);

    int write_contract_hp_inputs(execution_context &ctx);

    int write_npl_messages(execution_context &ctx);

    int read_contract_hp_npl_outputs(execution_context &ctx);

    // Common helper functions

    void fdmap_json_to_stream(const contract_fdmap_t &fdmap, std::ostringstream &os);

    int create_iopipes_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    int write_contract_fdmap_inputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    void cleanup_fdmap(contract_fdmap_t &fdmap);

    int create_iopipes(std::vector<int> &fds, const bool create_inpipe);

    int create_iosockets(std::vector<int> &fds);

    int write_iopipe(std::vector<int> &fds, std::list<std::string> &inputs);

    int read_iopipe(std::vector<int> &fds, std::string &output);

    int read_iosocket(std::vector<int> &fds, std::string &output);

    void close_unused_fds(execution_context &ctx, const bool is_hp);

    void close_unused_vectorfds(const bool is_hp, std::vector<int> &fds);

    void close_unused_socket_vectorfds(const bool is_hp, std::vector<int> &fds);

    void cleanup_vectorfds(std::vector<int> &fds);

    void clear_args(contract_execution_args &args);

    void stop(execution_context &ctx);

} // namespace sc

#endif