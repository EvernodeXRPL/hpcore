#ifndef _SOCK_SESSION_HANDLER_H_
#define _SOCK_SESSION_HANDLER_H_

#include "socket_session.h"
#include <boost/beast/core.hpp>

using error = boost::system::error_code;

namespace sock
{

// Forward declaration
class socket_session;

/** Represents an active WebSocket session handler
*/
class socket_session_handler
{
public:
    virtual void on_connect(const socket_session &session, error ec) = 0;
    virtual void on_message(const socket_session &session, std::shared_ptr<std::string const> const &message, error ec) = 0;
    virtual void on_close(const socket_session &session) = 0;
};
} // namespace sock

#endif