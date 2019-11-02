#ifndef _HP_USER_SESSION_HANDLER_
#define _HP_USER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"
#include "../sock/socket_message.hpp"

namespace usr
{

class user_session_handler : public sock::socket_session_handler<user_outbound_message>
{
public:
    void on_connect(sock::socket_session<user_outbound_message> *session);
    void on_message(sock::socket_session<user_outbound_message> *session, std::string_view message);
    void on_close(sock::socket_session<user_outbound_message> *session);
};

} // namespace usr

#endif