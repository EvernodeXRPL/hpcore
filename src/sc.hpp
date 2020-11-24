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
    constexpr uint16_t MAX_NPL_MSG_QUEUE_SIZE = 63;     // Maximum npl message queue size, The size passed is rounded to next number in binary sequence 1(1),11(3),111(7),1111(15),11111(31)....
    constexpr uint16_t MAX_CONTROL_MSG_QUEUE_SIZE = 63; // Maximum out message queue size, The size passed is rounded to next number in binary sequence 1(1),11(3),111(7),1111(15),11111(31)....

    // Enum used to differenciate socket fds maintained for SC socket.
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
        std::list<std::string> inputs;

        // List of outputs from the contract.
        std::list<contract_output> outputs;
    };

    // Common typedef for a map of pubkey->fdlist.
    // This is used to keep track of fdlist quadruplet with a public key (eg. user, npl).
    typedef std::unordered_map<std::string, std::vector<int>> contract_fdmap_t;

    // Common typedef for a map of pubkey->I/O list pair (input list and output list).
    // This is used to keep track of input/output buffers for a given public key (eg. user, npl)
    typedef std::unordered_map<std::string, contract_iobufs> contract_bufmap_t;

    /**
 * Holds information that should be passed into the contract process.
 */
    struct contract_execution_args
    {
        contract_execution_args()
            : npl_messages(MAX_NPL_MSG_QUEUE_SIZE),
              control_messages(MAX_CONTROL_MSG_QUEUE_SIZE)
        {
        }

        // Whether the contract should execute in read only mode (to serve read requests).
        bool readonly = false;

        // State dir path to be used for this execution.
        std::string state_dir;

        // Map of user I/O buffers (map key: user binary public key).
        // The value is a pair holding consensus-verified inputs and contract-generated outputs.
        contract_bufmap_t userbufs;

        // NPL messages to be passed into contract.
        moodycamel::ReaderWriterQueue<p2p::npl_message> npl_messages;

        // Contol messages to be passed into contract.
        moodycamel::ReaderWriterQueue<std::string> control_messages;

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

        // Map of user socket fds (map key: user public key)
        contract_fdmap_t userfds;

        // Socket fds for NPL <--> messages.
        std::vector<int> nplfds;

        // Socket fds for HP <--> messages.
        std::vector<int> hpscfds;

        // Holds the contract process id (if currently executing).
        pid_t contract_pid = 0;

        // Holds the hpfs rw process id (if currently executing).
        pid_t hpfs_pid = 0;

        // Thread to collect contract inputs and outputs and feed npl messages while contract is running.
        std::thread contract_monitor_thread;

        // Indicates that the contract has sent termination control message.
        bool termination_signaled = false;

        // Indicates that the deinit procedure has begun.
        bool is_shutting_down = false;
    };

    int init();

    void deinit();

    int execute_contract(execution_context &ctx);

    //------Internal-use functions for this namespace.

    int check_contract_exited(execution_context &ctx, const bool block);

    int start_hpfs_session(execution_context &ctx);

    int stop_hpfs_session(execution_context &ctx);

    int write_contract_args(const execution_context &ctx);

    void contract_monitor_loop(execution_context &ctx);

    int write_contract_hp_inputs(execution_context &ctx);

    int write_npl_messages(execution_context &ctx);

    int read_contract_hp_outputs(execution_context &ctx);

    int read_contract_npl_outputs(execution_context &ctx);

    void broadcast_npl_output(std::string_view output);

    // Common helper functions

    void fdmap_json_to_stream(const contract_fdmap_t &fdmap, std::ostringstream &os);

    int create_iosockets_for_fdmap(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    int write_contract_fdmap_inputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    int read_contract_fdmap_outputs(contract_fdmap_t &fdmap, contract_bufmap_t &bufmap);

    int create_iosockets(std::vector<int> &fds, const int socket_type);

    int write_iosocket_seq_packet(std::vector<int> &fds, std::string_view input);

    int write_iosocket_stream(std::vector<int> &fds, std::list<std::string> &inputs);

    int read_iosocket(const bool is_stream_socket, std::vector<int> &fds, std::string &output);

    void close_unused_fds(execution_context &ctx, const bool is_hp);

    void close_unused_socket_vectorfds(const bool is_hp, std::vector<int> &fds);

    void cleanup_vectorfds(std::vector<int> &fds);

    void stop(execution_context &ctx);

    void handle_control_msgs(execution_context &ctx, std::string &msg);

} // namespace sc

#endif