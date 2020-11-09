#ifndef _HP_USR_USER_COMM_SESSION_
#define _HP_USR_USER_COMM_SESSION_

#include "../pchheader.hpp"
#include "../comm/comm_session.hpp"

namespace usr
{
    /** 
     * Represents a WebSocket connection to a Hot Pocket user.
     */
    class user_comm_session : public comm::comm_session
    {
        using comm_session::comm_session; // Inherit constructors.

    private:
        void handle_connect();
        int handle_message(std::string_view msg);
        void handle_close();

    public:
        const std::string display_name();
    };

} // namespace usr

#endif
