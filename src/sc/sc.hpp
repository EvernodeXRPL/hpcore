#ifndef _HP_SC_SC_
#define _HP_SC_SC_

#include "../pchheader.hpp"
#include "../usr/usr.hpp"
#include "../util/h32.hpp"
#include "../util/util.hpp"
#include "../util/buffer_store.hpp"
#include "../p2p/p2p.hpp"
#include "contract_mount.hpp"
#include "contract_sync.hpp"

/**
 * Contains helper functions regarding POSIX process execution and IPC between HP and SC.
 */
namespace sc
{
    constexpr uint16_t MAX_NPL_MSG_QUEUE_SIZE = 64;     // Maximum npl message queue size, The size passed is rounded to next number in binary sequence 1(1),11(3),111(7),1111(15),11111(31)....
    constexpr uint16_t MAX_CONTROL_MSG_QUEUE_SIZE = 64; // Maximum out message queue size, The size passed is rounded to next number in binary sequence 1(1),11(3),111(7),1111(15),11111(31)....

    struct fd_pair
    {
        int hpfd = -1;
        int scfd = -1;
    };

    /**
     * Stores contract output message length along with the message. Length is used to construct the message from the stream buffer.
    */
    struct contract_output
    {
        uint32_t message_len = 0;
        std::string message;
    };

    /**
     * Represents list of inputs to the contract and the accumulated contract output for those inputs.
     */
    struct contract_iobufs
    {
        // List of inputs to be fed into the contract.
        std::vector<util::buffer_view> inputs;

        // List of outputs from the contract.
        std::list<contract_output> outputs;

        // Total output bytes accumulated so far.
        size_t total_output_len = 0;
    };

    // Common typedef for a map of pubkey->fdpair.
    // This is used to keep track of fdpair with a public key (eg. user).
    typedef std::map<std::string, fd_pair> contract_fdmap_t;

    // Common typedef for a map of pubkey->I/O list pair (input list and output list).
    // This is used to keep track of input/output buffers for a given public key (eg. user)
    typedef std::map<std::string, contract_iobufs> contract_bufmap_t;

    /**
     * Holds information that should be passed into the contract process.
     */
    struct contract_execution_args
    {
        // Whether the contract should execute in read only mode (to serve read requests).
        bool readonly = false;

        // hpfs session name used for this execution.
        std::string hpfs_session_name;

        // Map of user I/O buffers (map key: user binary public key).
        // The value is a pair holding consensus-verified inputs and contract-generated outputs.
        contract_bufmap_t userbufs;

        util::buffer_store &user_input_store;

        // NPL messages to be passed into contract.
        moodycamel::ReaderWriterQueue<p2p::npl_message> npl_messages;

        // Contol messages to be passed into contract.
        moodycamel::ReaderWriterQueue<std::string> control_messages;

        // Current HotPocket consensus time.
        uint64_t time = 0;

        // Current HotPocket lcl (seq no. and ledger hash hex)
        p2p::sequence_hash lcl_id;

        // State hash after execution will be copied to this (not applicable to read only mode).
        util::h32 post_execution_state_hash = util::h32_empty;

        contract_execution_args(util::buffer_store &user_input_store)
            : user_input_store(user_input_store),
              npl_messages(MAX_NPL_MSG_QUEUE_SIZE),
              control_messages(MAX_CONTROL_MSG_QUEUE_SIZE)
        {
        }
    };

    /**
     * Holds context information relating to contract execution environment.
     */
    struct execution_context
    {
        // The arguments that was used to initiate this execution.
        contract_execution_args args;

        // Map of user socket fds (map key: user public key)
        contract_fdmap_t user_fds;

        // Socket fds for NPL messages.
        fd_pair npl_fds;

        // Socket fds for control messages.
        fd_pair control_fds;

        // Holds the contract process id (if currently executing).
        pid_t contract_pid = 0;

        // Thread to collect contract inputs and outputs and feed npl messages while contract is running.
        std::thread contract_monitor_thread;

        size_t total_npl_output_size = 0;

        // The path set as contract working directory.
        std::string working_dir;

        // Full paths to std out/err log files for the contract execution.
        std::string stdout_file;
        std::string stderr_file;

        // Indicates that the contract has sent termination control message.
        bool termination_signaled = false;

        // Indicates whether the contract exited normally without any errors.
        bool exit_success = false;

        // Indicates that the hpcore deinit procedure has begun.
        bool is_shutting_down = false;

        execution_context(util::buffer_store &user_input_store) : args(user_input_store)
        {
        }
    };

    extern sc::contract_mount contract_fs;         // Global contract file system instance.
    extern sc::contract_sync contract_sync_worker; // Global contract file system sync instance.

    int init();

    void deinit();

    int execute_contract(execution_context &ctx);

    //------Internal-use functions for this namespace.

    int set_process_rlimits();

    int check_contract_exited(execution_context &ctx, const bool block);

    int start_hpfs_session(execution_context &ctx);

    int stop_hpfs_session(execution_context &ctx);

    int write_contract_args(const execution_context &ctx, const int user_inputs_fd);

    void contract_monitor_loop(execution_context &ctx);

    int run_post_exec_script(const execution_context &ctx);

    int write_control_inputs(execution_context &ctx);

    int write_npl_messages(execution_context &ctx);

    int read_control_outputs(execution_context &ctx, const pollfd pfd);

    int read_npl_outputs(execution_context &ctx, pollfd *pfd);

    void broadcast_npl_output(std::string_view output);

    // Common helper functions

    void user_json_to_stream(const contract_fdmap_t &user_fdmap, const contract_bufmap_t &user_bufmap, std::ostringstream &os);

    int create_iosockets_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, pollfd *pfds, contract_bufmap_t &bufmap);

    int create_contract_log_files(execution_context &ctx);

    int create_iosockets(fd_pair &fds, const int socket_type);

    int write_iosocket_seq_packet(fd_pair &fds, std::string_view input);

    int read_iosocket(const bool is_stream_socket, const pollfd pfd, std::string &output);

    void close_unused_fds(execution_context &ctx, const bool is_hp);

    void close_unused_socket_fds(const bool is_hp, fd_pair &fds);

    void cleanup_fds(execution_context &ctx);

    void cleanup_fd_pair(fd_pair &fds);

    void stop(execution_context &ctx);

    void handle_control_msg(execution_context &ctx, std::string_view msg);

} // namespace sc

#endif