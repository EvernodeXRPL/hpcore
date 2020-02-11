#ifndef _HP_COMM_SESSION_HANDLER_
#define _HP_COMM_SESSION_HANDLER_

#include "../pchheader.hpp"

namespace comm
{

// Forward declaration
class comm_session;

class comm_session_handler
{

public:
    void on_connect(comm_session &session);
    void on_message(comm_session &session, std::string_view message);
    void on_close(comm_session &session);
};

} // namespace comm

#endif