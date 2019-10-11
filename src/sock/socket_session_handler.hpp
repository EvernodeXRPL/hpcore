#ifndef _SOCK_SESSION_HANDLER_H_
#define _SOCK_SESSION_HANDLER_H_

#include "socket_session.hpp"

namespace sock
{

// Forward declaration
class socket_session;

/** 
 * Represents a WebSocket sessions handler. Can inherit from this class and access websocket events
*/
class socket_session_handler
{
public:
    virtual void on_connect(socket_session *session) = 0;
    virtual void on_message(socket_session *session, const std::string &message) = 0;
    virtual void on_close(socket_session *session) = 0;
};
} // namespace sock

#endif