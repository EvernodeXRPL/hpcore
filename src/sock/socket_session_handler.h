#ifndef _SOCK_SESSION_HANDLER_H_
#define _SOCK_SESSION_HANDLER_H_

#include "socket_session.h"
#include <boost/beast/core.hpp>

using error = boost::system::error_code;

namespace sock
{

// Forward declaration
class socket_session;

/** Represents an active WebSocket session handler. Can inherit from this class and access events (read, write)
*/
class socket_session_handler
{
public:
    //On successful websocket session creation after handshake
    virtual void on_connect(socket_session *session, error ec) = 0;
    //On message recieved
    virtual void on_message(socket_session *session, std::shared_ptr<std::string const> const &message, error ec) = 0;
    //On closing web socket connection
    virtual void on_close(socket_session *session) = 0;
};
} // namespace sock

#endif