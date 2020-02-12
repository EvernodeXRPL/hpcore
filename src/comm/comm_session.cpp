#include "../pchheader.hpp"
#include "../usr/user_session_handler.hpp"
#include "comm_session.hpp"
#include "../hplog.hpp"

namespace comm
{

// Global instance of user session handler.
usr::user_session_handler user_sess_handler;

comm_session::comm_session(const int fd, const SESSION_TYPE session_type)
    : session_fd(fd), session_type(session_type), uniqueid(std::to_string(fd))
{
}

void comm_session::on_connect()
{
    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_connect(*this);
}

void comm_session::on_message(std::string_view message)
{
    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_message(*this, message);
}

void comm_session::send(std::string_view message) const
{
    // We need to append every message with '\n'
    // Prepare the memory segments to map with writev().
    iovec memsegs[2];
    memsegs[0].iov_base = (char *)message.data();
    memsegs[0].iov_len = message.length();
    memsegs[1].iov_base = (char *)"\n";
    memsegs[1].iov_len = 1;

    if (writev(session_fd, memsegs, 2) == -1)
        LOG_ERR << errno << ": Session send writev failed.";
}

void comm_session::close()
{
    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_close(*this);

    ::close(session_fd);
    flags.set(SESSION_FLAG::CLOSED);
}

} // namespace comm