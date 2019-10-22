#include <boost/beast/core.hpp>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

namespace usr
{

class user_outbound_message : public sock::outbound_message
{
    std::string msg;

public:
    user_outbound_message(std::string &&_msg);
    virtual std::string_view buffer();
};

class user_session_handler : public sock::socket_session_handler<user_outbound_message>
{
public:
    void on_connect(sock::socket_session<user_outbound_message> *session);
    void on_message(sock::socket_session<user_outbound_message> *session, std::string_view message);
    void on_close(sock::socket_session<user_outbound_message> *session);
};

} // namespace usr