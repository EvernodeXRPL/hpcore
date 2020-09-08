#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"
#include "comm_session_threshold.hpp"
#include "../conf.hpp"
#include <queue>
#include <thread>
#include <mutex>

namespace comm
{

    enum CHALLENGE_STATUS
    {
        CHALLENGE_ISSUED,
        CHALLENGE_VERIFIED
    };

    enum SESSION_STATE
    {
        ACTIVE,
        CLOSED
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
        const int write_fd = 0; // Only valid for outgoing client connections.
        const SESSION_TYPE session_type;
        std::vector<session_threshold> thresholds; // track down various communication thresholds
        uint32_t expected_msg_size = 0;            // Next expected message size based on size header.
        std::vector<char> read_buffer;             // Local buffer to keep collecting data until a complete message can be constructed.
        uint32_t read_buffer_filled_size = 0;      // How many bytes have been buffered so far.

        int get_binary_msg_read_len(const size_t available_bytes);
        int on_message(std::string_view message);

    public:
        const std::string address; // IP address of the remote party.
        const bool is_binary;
        const bool is_inbound;
        bool is_self = false;
        std::string uniqueid;
        std::string issued_challenge;
        conf::ip_port_pair known_ipport;
        SESSION_STATE state;
        CHALLENGE_STATUS challenge_status;

        comm_session(
            std::string_view ip, const int read_fd, const int write_fd, const SESSION_TYPE session_type,
            const bool is_binary, const bool is_inbound, const uint64_t (&metric_thresholds)[4]);
        int on_connect();
        int attempt_read(const uint64_t max_msg_size);
        int send(const std::vector<uint8_t> &message) const;
        int send(std::string_view message) const;
        void add_msg_to_outbound_queue(std::string_view message);
        //void comm_session::process_outbound_msg_queue();
        void close(const bool invoke_handler = true);

        void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
        void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);

    private:
        std::queue<std::string_view> queue;
        std::mutex *mutex;
    };

} // namespace comm

#endif