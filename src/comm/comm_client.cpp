#include "comm_client.hpp"
#include "comm_session.hpp"
#include "comm_session_handler.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace comm
{

    int comm_client::start(std::string_view host, const uint16_t port, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size)
    {
        return start_websocat_process(host, port);
    }

    void comm_client::stop()
    {
        if (read_fd > 0)
            close(read_fd);
        if (write_fd > 0)
            close(write_fd);

        if (websocat_pid > 0)
            util::kill_process(websocat_pid, false); // Kill websocat.
    }

    int comm_client::start_websocat_process(std::string_view host, const uint16_t port)
    {
        // setup pipe I/O
        if (pipe(read_pipe) < 0 || pipe(write_pipe) < 0)
        {
            LOG_ERR << errno << ": websocat pipe creation failed.";
            return -1;
        }

        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.

            read_fd = read_pipe[0];
            write_fd = write_pipe[1];

            // Close unused fds by us.
            close(write_pipe[0]);
            close(read_pipe[1]);

            // Wait for some time and check if websocat process has closed the pipe.
            util::sleep(300);
            pollfd fds[1] = {{read_fd}};
            if (poll(fds, 1, 0) == -1 || (fds[0].revents & POLLHUP))
            {
                close(read_fd);
                close(write_fd);
                
                util::kill_process(pid, false);
                return -1;
            }

            websocat_pid = pid;
        }
        else if (pid == 0)
        {
            // Websocat process.
            util::unmask_signal();
            
            close(write_pipe[1]); //parent write
            close(read_pipe[0]);  //parent read

            dup2(write_pipe[0], STDIN_FILENO); //child read
            close(write_pipe[0]);
            dup2(read_pipe[1], STDOUT_FILENO); //child write
            close(read_pipe[1]);

            std::string url = std::string("wss://").append(host).append(":").append(std::to_string(port));

            // Fill process args.
            char *execv_args[] = {
                conf::ctx.websocat_exe_path.data(),
                url.data(),
                (char *)"-k", // Accept invalid certificates
                (char *)"-b", // Binary mode
                (char *)"-E", // Close on EOF
                (char *)"-q", // Quiet mode
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERR << errno << ": websocat process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERR << "fork() failed when starting websocat process.";
            return -1;
        }

        return 0;
    }

} // namespace comm
