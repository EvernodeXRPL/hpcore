#ifndef _HP_COMM_SESSION_
#define _HP_COMM_SESSION_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"

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
    USER_CHALLENGE_ISSUED = 1,
    USER_AUTHED = 2
};

//Forward Declaration
class comm_session_handler;

/** 
 * Represents an active WebSocket connection
*/
class comm_session
{

    comm_session_handler &sess_handler;

public:
    // The unique identifier of the remote party (format <ip>:<port>).
    const std::string uniqueid;

    // Boolean value to store whether the session is self connection (connect to the same node)
    bool is_self;

    // The set of SESSION_FLAG enum flags that will be set by user-code of this calss.
    // We mainly use this to store contexual information about this session based on the use case.
    // Setting and reading flags to this is completely managed by user-code.
    std::bitset<8> flags;

    comm_session(std::string uniqueid, comm_session_handler &sess_handler);
    void on_connect();
    void on_message(std::string_view message);
    void on_close();
};

} // namespace comm

#endif