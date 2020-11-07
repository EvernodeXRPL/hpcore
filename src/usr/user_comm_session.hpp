#ifndef _HP_USR_USER_COMM_SESSION_
#define _HP_USR_USER_COMM_SESSION_

#include "../pchheader.hpp"
#include "../comm/comm_session.hpp"

namespace comm
{
    /** 
     * Represents a WebSocket connection to a Hot Pocket user.
     */
    class user_comm_session : public comm_session
    {
        using comm_session::comm_session; // Inherit constructors.

    private:
        int handle_connect();
        int handle_message(std::string_view msg);
        int handle_close();
    };

} // namespace comm

#endif
