#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"
#include "comm_session_threshold.hpp"

namespace comm
{

/**
 * Set of flags used to mark status information on the session.
 * usr and p2p subsystems makes use of this to mark status information of user and peer sessions.
 * Set flags are stored in 'flags' bitset of comm_session.
 */
enum SESSION_FLAG
{
    USER_CHALLENGE_ISSUED,
    USER_AUTHED
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
    const int session_fd;
    const SESSION_TYPE session_type;
    std::vector<session_threshold> thresholds; // track down various communication thresholds
    uint32_t expected_msg_size = 0;            // Next expected message size based on size header.

    uint32_t get_binary_msg_read_len(const size_t available_bytes);
    void on_message(std::string_view message);

public:
    // The unique identifier of the remote party (format <ip>:<port>).
    const std::string uniqueid;

    // IP address of the remote party.
    const std::string address;

    const bool is_binary;
    SESSION_STATE state;

    // The set of SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags;

    comm_session(std::string_view ip, const int fd, const SESSION_TYPE session_type, const bool is_binary, const uint64_t (&metric_thresholds)[4]);
    void on_connect();
    void attempt_read(bool &should_disconnect, const uint64_t max_msg_size);
    void send(std::string_view message) const;
    void close();

    void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
    void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);
};

} // namespace comm

#endif