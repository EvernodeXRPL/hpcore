#ifndef _HP_USER_SESSION_HANDLER_
#define _HP_USER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "user_comm_session.hpp"

namespace usr
{
    void handle_user_connect(usr::user_comm_session &session);
    int handle_user_message(usr::user_comm_session &session, std::string_view message);
    int handle_user_close(const usr::user_comm_session &session);

} // namespace usr

#endif