#ifndef _HP_USR_USER_COMM_SERVER_
#define _HP_USR_USER_COMM_SERVER_

#include "../status.hpp"
#include "../comm/comm_server.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "usr.hpp"
#include "user_comm_session.hpp"

namespace usr
{
    // Forward declaration. Defined in usr.cpp.
    void dispatch_change_events();

    class user_comm_server : public comm::comm_server<user_comm_session>
    {
        using comm::comm_server<user_comm_session>::comm_server; // Inherit constructors.

    protected:
        int process_custom_messages()
        {
            usr::dispatch_change_events();
            return 0;
        }
    };
} // namespace usr

#endif