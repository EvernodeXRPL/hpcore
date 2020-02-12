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
    void on_connect(comm_session &session) const;
    void on_message(comm_session &session, std::string_view message) const;
    void on_close(const comm_session &session) const;
};

} // namespace comm

#endif