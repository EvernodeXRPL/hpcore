#include "debug_shell.hpp"

namespace debug_shell
{
    constexpr uint8_t DEBUG_SHELL_CTRL_TERMINATE = 0;
    constexpr uint8_t DEBUG_SHELL_CTRL_SH = 1;
    constexpr uint32_t POLL_TIMEOUT = 1000;
    constexpr uint32_t READ_BUFFER_SIZE = 128 * 1024;

    debug_shell_context ctx;

    int init()
    {
        // Do not initialize if disabled in config.
        if (!conf::cfg.debug_shell.enabled)
            return 0;

        // Create a socket pair for the control channel.
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctx.control_fds) == -1)
        {
            LOG_ERROR << errno << ": Error initializing socket pair.";
            return -1;
        }

        // Create a child process for debug_shell process
        ctx.debug_shell_pid = fork();
        if (ctx.debug_shell_pid == -1)
        {
            LOG_ERROR << errno << ": Error forking hpfs process.";
            close(ctx.control_fds[0]);
            close(ctx.control_fds[1]);
            return -1;
        }
        else if (ctx.debug_shell_pid > 0)
        {
            // Close child end of socket and start the watcher thread.
            close(ctx.control_fds[0]);

            ctx.watcher_thread = std::thread(response_watcher);
        }
        else if (ctx.debug_shell_pid == 0)
        {
            util::fork_detach();

            close(ctx.control_fds[1]);

            std::string fd_str;
            fd_str.resize(10);
            snprintf(fd_str.data(), 10, "%d", ctx.control_fds[0]);

            char *argv[] = {(char *)conf::ctx.debug_shell_exe_path.data(), fd_str.data(), NULL};

            // Just before we execv the debug_shell binary, we set user execution user/group if specified in hp config.
            // (Must set gid before setting uid)
            if (!conf::cfg.debug_shell.run_as.empty() && (setgid(conf::cfg.debug_shell.run_as.gid) == -1 || setuid(conf::cfg.debug_shell.run_as.uid) == -1))
            {
                std::cerr << errno << ": DebugShell process setgid/uid failed."
                          << "\n";
                exit(1);
            }

            execv(argv[0], argv);

            std::cerr << errno << ": Error executing debug_shell."
                      << "\n";

            close(ctx.control_fds[0]);
            exit(1);
        }

        ctx.is_initialized = true;

        LOG_INFO << "DebugShell handler started.";

        return 0;
    }

    void deinit()
    {
        // This is not initialized if disabled in config.
        if (!conf::cfg.debug_shell.enabled)
            return;

        ctx.is_shutting_down = true;

        if (ctx.debug_shell_pid > 0)
            send_terminate_message();

        // Joining consensus processing thread.
        if (ctx.watcher_thread.joinable())
            ctx.watcher_thread.join();

        // close sockets.
        close(ctx.control_fds[0]);
        for (const auto &command : ctx.commands)
        {
            close(command.out_fd);
        }

        if (ctx.debug_shell_pid > 0)
        {
            // Check if the debug_shell has exited voluntarily.
            if (check_debug_shell_exited(false) == 0)
            {
                // Issue kill signal to kill the debug_shell process.
                kill(ctx.debug_shell_pid, SIGKILL);
                check_debug_shell_exited(true); // Blocking wait until exit.
            }
        }

        LOG_INFO << "DebugShell handler stopped.";
    }

    int check_debug_shell_exited(const bool block)
    {
        int scstatus = 0;
        const int wait_res = waitpid(ctx.debug_shell_pid, &scstatus, block ? 0 : WNOHANG);

        if (wait_res == 0) // Child still running.
        {
            return 0;
        }
        if (wait_res == -1)
        {
            LOG_ERROR << errno << ": DebugShell process waitpid error. pid:" << ctx.debug_shell_pid;
            ctx.debug_shell_pid = 0;
            return -1;
        }
        else // Child has exited
        {
            ctx.debug_shell_pid = 0;

            if (WIFEXITED(scstatus))
            {
                LOG_DEBUG << "DebugShell process ended normally.";
                return 1;
            }
            else
            {
                LOG_WARNING << "DebugShell process ended prematurely. Exit code " << WEXITSTATUS(scstatus);
                return -1;
            }
        }
    }

    int send_terminate_message()
    {
        return (write(ctx.control_fds[1], &DEBUG_SHELL_CTRL_TERMINATE, 1) < 0) ? -1 : 0;
    }

    void remove_user_commands(std::string_view user_pubkey)
    {
        std::scoped_lock lock(ctx.command_mutex);
        // Loop for all the child commands and delete the commands belongs to the user.
        auto itr = ctx.commands.begin();
        while (itr != ctx.commands.end())
        {
            if (itr->user_pubkey == user_pubkey)
            {
                // Close the file descriptor and remove the command from context.
                close(itr->out_fd);
                itr = ctx.commands.erase(itr);
            }
            else
            {
                itr++;
            }
        }
    }

    int execute(std::string_view id, std::string_view user_pubkey, std::string_view message)
    {
        if (ctx.is_shutting_down)
            return -1;

        if (conf::cfg.debug_shell.users.find(std::string(user_pubkey)) == conf::cfg.debug_shell.users.end())
        {
            LOG_ERROR << "This user is not allowed to perform debug_shell operations.";
            return -2;
        }

        std::string buffer;
        buffer.resize(message.size() + 1);
        buffer[0] = DEBUG_SHELL_CTRL_SH;
        memcpy(buffer.data() + 1, message.data(), message.size());

        // Send the debug_shell request header.
        if (write(ctx.control_fds[1], buffer.data(), message.size() + 1) < 0)
        {
            LOG_ERROR << errno << ": Error writing header message to control fd.";
            return -1;
        }

        // Read the control message which will contain the socket file descriptor.
        struct msghdr child_msg = {0};
        memset(&child_msg, 0, sizeof(child_msg));
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        child_msg.msg_control = cmsgbuf;
        child_msg.msg_controllen = sizeof(cmsgbuf);

        recvmsg(ctx.control_fds[1], &child_msg, 0);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&child_msg);

        // Skip if the message does not has file descriptor scm rights.
        if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
        {
            LOG_ERROR << "Message sent on control line from debug_shell has non-scm_rights.";
            return -1;
        }

        int out_fd = -1;
        memcpy(&out_fd, CMSG_DATA(cmsg), sizeof(out_fd));

        if (out_fd <= 0)
        {
            LOG_ERROR << "Invalid file descriptor receives on control line from debug_shell";
            return -1;
        }

        // Add the command to the context.
        {
            std::scoped_lock lock(ctx.command_mutex);
            ctx.commands.push_back(command_context{std::string(id), std::string(user_pubkey), out_fd});
        }

        return 0;
    }

    void response_watcher()
    {
        util::mask_signal();

        while (!ctx.is_shutting_down)
        {
            // Iterate through received commands and check for outputs.
            if (ctx.commands.size() > 0)
            {
                std::scoped_lock<std::mutex> lock(ctx.command_mutex);

                auto itr = ctx.commands.begin();
                while (itr != ctx.commands.end())
                {
                    if (ctx.is_shutting_down)
                        break;

                    struct pollfd pfd;
                    pfd.fd = itr->out_fd;
                    pfd.events = POLLIN;

                    bool remove = false;

                    // If child fd has data to read handle them.
                    const int poll_res = poll(&pfd, 1, POLL_TIMEOUT);
                    if (poll_res == -1)
                    {
                        LOG_ERROR << errno << ": Error in poll";
                        remove = true;
                    }
                    else if (poll_res > 0 && (pfd.revents & POLLIN))
                    {
                        // Read the response and send to the user.
                        std::string response;
                        response.resize(READ_BUFFER_SIZE);
                        const int res = read(pfd.fd, response.data(), READ_BUFFER_SIZE);
                        if (res > 0)
                        {
                            response.resize(res);

                            // If response contains trailing new line, Remove it.
                            if (response[res - 1] == '\n')
                                response[res - 1] = '\0';

                            std::scoped_lock<std::mutex> lock(usr::ctx.users_mutex);

                            // Find the user session by user pubkey.
                            const auto user_itr = usr::ctx.users.find(itr->user_pubkey);
                            if (user_itr != usr::ctx.users.end()) // match found
                            {
                                const usr::connected_user &user = user_itr->second;
                                msg::usrmsg::usrmsg_parser parser(user.protocol);
                                usr::send_debug_shell_response(std::move(parser), user.session, itr->id, msg::usrmsg::STATUS_ACCEPTED, response);
                                response.clear();
                            }
                        }
                        else if (res == -1)
                        {
                            LOG_ERROR << errno << ": Error reading from fd.";
                            remove = true;
                        }
                        else
                        {
                            LOG_DEBUG << "DebugShell has closed the connection.";
                            remove = true;
                        }
                    }

                    if (remove)
                    {
                        // Close the file descriptor and remove the command from context.
                        close(itr->out_fd);
                        itr = ctx.commands.erase(itr);
                    }
                    else
                    {
                        itr++;
                    }
                }
            }
            util::sleep(100);
        }
    }
}