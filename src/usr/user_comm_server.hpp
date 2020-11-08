#ifndef _HP_USR_USER_COMM_SERVER_
#define _HP_USR_USER_COMM_SERVER_

#include "../comm/comm_server.hpp"
#include "user_comm_session.hpp"

namespace usr
{
    class user_comm_server : public comm::comm_server<user_comm_session>
    {
        using comm::comm_server<user_comm_session>::comm_server; // Inherit constructors.
    };
} // namespace usr

#endif