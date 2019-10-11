#include <boost/beast/core.hpp>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

using error = boost::system::error_code;

namespace usr
{

class user_session_handler : public sock::socket_session_handler
{
public:
    void on_connect(sock::socket_session *session);
    void on_message(sock::socket_session *session, const std::string &message);
    void on_close(sock::socket_session *session);
};

}