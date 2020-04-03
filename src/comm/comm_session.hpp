#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"
#include "comm_session_threshold.hpp"
#include "../conf.hpp"

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
    USER_AUTHED,
    PEERID_RESOLVED
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

    uint32_t get_binary_msg_read_len(const size_t available_bytes);
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

    // The set of SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags;

    comm_session(
        std::string_view ip, const int read_fd, const int write_fd, const SESSION_TYPE session_type,
        const bool is_binary, const bool is_inbound, const uint64_t (&metric_thresholds)[4]);
    int on_connect();
    int attempt_read(const uint64_t max_msg_size);
    int send(std::string_view message) const;
    void close(const bool invoke_handler = true);

    void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
    void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);
};

} // namespace comm

#endif