#include "../pchheader.hpp"
#include "user_comm_session.hpp"
#include "user_session_handler.hpp"

namespace comm
{
    int user_comm_session::handle_connect()
    {
        return usr::handle_user_connect(*this);
    }

    int user_comm_session::handle_message(std::string_view msg)
    {
        return usr::handle_user_message(*this, msg);
    }

    int user_comm_session::handle_close()
    {
        return usr::handle_user_close(*this);
    }

} // namespace comm