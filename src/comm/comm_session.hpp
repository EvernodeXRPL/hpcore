#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"
#include "comm_session_threshold.hpp"
#include "../conf.hpp"

namespace comm
{

    enum CHALLENGE_STATUS
    {
        NOT_ISSUED,
        CHALLENGE_ISSUED,
        CHALLENGE_VERIFIED
    };

    enum SESSION_STATE
    {
        NOT_INITIALIZED,       // Session is not yet initialized properly.
        ACTIVE,     // Session is active and functioning.
        MUST_CLOSE, // Session socket is in unusable state and must be closed.
        CLOSED      // Session is fully closed.
    };

    enum SESSION_TYPE
    {
        USER = 0,
        PEER = 1
    };

    /** 
 * Represents an active WebSocket connection
*/
    class comm_session
    {
        const int read_fd = 0;
        const int write_fd = 0;
        const SESSION_TYPE session_type;
        const uint64_t max_msg_size = 0;
        std::vector<session_threshold> thresholds;                  // track down various communication thresholds
        uint32_t expected_msg_size = 0;                             // Next expected message size based on size header.
        std::vector<char> read_buffer;                              // Local buffer to keep collecting data until a complete message can be constructed.
        uint32_t read_buffer_filled_size = 0;                       // How many bytes have been buffered so far.
        bool should_stop_data_threads = false;                      // Indicates whether data threads has been instructed to stop.
        std::thread reader_thread;                                  // The thread responsible for reading data from the socket.
        moodycamel::ReaderWriterQueue<std::vector<char>> msg_queue; // Holds incoming messages waiting to be processed.

        void reader_loop();
        int attempt_read();
        int attempt_binary_msg_construction(const size_t available_bytes);

    public:
        const std::string address; // IP address of the remote party.
        const bool is_binary;
        const bool is_inbound;
        bool is_self = false;
        std::string uniqueid;
        std::string issued_challenge;
        conf::ip_port_pair known_ipport;
        SESSION_STATE state = SESSION_STATE::NOT_INITIALIZED;
        CHALLENGE_STATUS challenge_status = CHALLENGE_STATUS::NOT_ISSUED;

        comm_session(
            std::string_view ip, const int read_fd, const int write_fd, const SESSION_TYPE session_type,
            const bool is_binary, const bool is_inbound, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size);
        int on_connect();
        void start_data_threads();
        int process_queued_message();
        int send(const std::vector<uint8_t> &message) const;
        int send(std::string_view message) const;
        void close(const bool invoke_handler = true);

        void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
        void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);
    };

} // namespace comm

#endif