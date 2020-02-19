#ifndef _HP_COMM_CLIENT_
#define _HP_COMM_CLIENT_

#include "../pchheader.hpp"
#include "comm_session.hpp"

namespace comm
{

class comm_client
{
    pid_t websocat_pid = 0;
    int read_pipe[2];     // parent to child pipe
    int write_pipe[2];    // child to parent pipe
    
    int start_websocat_process(std::string_view host, const uint16_t port);

public:
    int read_fd = 0, write_fd = 0;

    int start(std::string_view host, const uint16_t port, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size);
    void stop();
};

} // namespace comm

#endif
