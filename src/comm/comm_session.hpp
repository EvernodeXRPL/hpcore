#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"

namespace comm
{

/**
 * Set of flags used to mark status information on the session.
 * usr and p2p subsystems makes use of this to mark status information of user and peer sessions.
 * Set flags are stored in 'flags' bitset of comm_session.
 */
enum SESSION_FLAG
{
    INBOUND = 0,
    CLOSED = 1,
    USER_CHALLENGE_ISSUED = 2,
    USER_AUTHED = 3
};

/**
 * Socket session type.
 */
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

public:
    // The unique identifier of the remote party (format <ip>:<port>).
    const std::string uniqueid;

    // IP address of the remote party.
    const std::string address;

    // The set of SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags;

    comm_session(const int fd, const SESSION_TYPE session_type);
    void on_connect();
    void on_message(std::string_view message);
    void send(std::string_view message) const;
    void close();
};

} // namespace comm

#endif