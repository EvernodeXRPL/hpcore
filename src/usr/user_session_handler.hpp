#include <boost/beast/core.hpp>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

namespace usr
{

class user_session_handler : public sock::socket_session_handler
{
public:
    void on_connect(sock::socket_session *session);
    void on_message(sock::socket_session *session, std::string_view message);
    void on_close(sock::socket_session *session);
};

} // namespace usr