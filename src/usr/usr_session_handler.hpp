#include <boost/beast/core.hpp>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

using error = boost::system::error_code;

namespace usr
{

class usr_session_handler : public sock::socket_session_handler
{
public:
    void on_connect(sock::socket_session *session, error ec);
    void on_message(sock::socket_session *session, std::shared_ptr<std::string const> const &message, error ec);
    void on_close(sock::socket_session *session);
};

}