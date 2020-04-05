#ifndef _HP_USER_SESSION_HANDLER_
#define _HP_USER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "../comm/comm_session_handler.hpp"
#include "../comm/comm_session.hpp"

namespace usr
{

class user_session_handler : public comm::comm_session_handler
{
public:
    int on_connect(comm::comm_session &session) const;
    int on_message(comm::comm_session &session, std::string_view message) const;
    void on_close(const comm::comm_session &session) const;
};

} // namespace usr

#endif