#include <boost/beast/core.hpp>
#include "sock/socket_session_handler.h"
#include "sock/socket_session.h"

using error = boost::system::error_code;

class peer_session_handler : public sock::socket_session_handler
{
public:
    void on_connect(const sock::socket_session &session, error ec);
    void on_message(const sock::socket_session &session, std::shared_ptr<std::string const> const &message, error ec);
    void on_close(const sock::socket_session &session);
};