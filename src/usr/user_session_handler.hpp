#ifndef _HP_USER_SESSION_HANDLER_
#define _HP_USER_SESSION_HANDLER_

#include "../pchheader.hpp"
#include "../comm/hpws_comm_session.hpp"

namespace usr
{
    int handle_user_connect(comm::hpws_comm_session &session);
    int handle_user_message(comm::hpws_comm_session &session, std::string_view message);
    int handle_user_close(const comm::hpws_comm_session &session);

} // namespace usr

#endif