#ifndef _HP_USER_SESSION_HANDLER_H_
#define _HP_USER_SESSION_HANDLER_H_

#include "../pchheader.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

namespace usr
{

/**
 * Represents a message (bytes) that is sent to a user.
 */
class user_outbound_message : public sock::outbound_message
{
    // Contains message bytes.
    std::string msg;

public:
    user_outbound_message(std::string &&_msg);

    // Returns the buffer that should be written to the socket.
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

#endif