#include "hpsh.hpp"

namespace hpsh
{
    constexpr const char *HPSH_CTR_SH = "sh";
    constexpr const char *HPSH_CTR_TERMINATE = "terminate";
    constexpr uint32_t POLL_TIMEOUT = 1000;
    constexpr uint32_t READ_BUFFER_SIZE = 128 * 1024;

    hpsh_context ctx;

    int init()
    {
        // Do not initialize if disabled in config.
        if (!conf::cfg.hpsh.enabled)
            return 0;

        // Create a socket pair for the control channel.
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctx.control_fds) == -1)
        {
            LOG_ERROR << errno << ": Error initializing socket pair.";
            return -1;
        }

        // Create a child process for hpsh process
        ctx.hpsh_pid = fork();
        if (ctx.hpsh_pid == -1)
        {
            LOG_ERROR << errno << ": Error forking hpfs process.";
            close(ctx.control_fds[0]);
            close(ctx.control_fds[1]);
            return -1;
        }
        else if (ctx.hpsh_pid > 0)
        {
            // Close child end of socket and start the watcher thread.
            close(ctx.control_fds[0]);

            ctx.watcher_thread = std::thread(response_watcher);
        }
        else if (ctx.hpsh_pid == 0)
        {
            util::fork_detach();

            close(ctx.control_fds[1]);

            std::string fd_str;
            fd_str.resize(10);
            snprintf(fd_str.data(), 10, "%d", ctx.control_fds[0]);

            char *argv[] = {(char *)conf::ctx.hpsh_exe_path.data(), fd_str.data(), NULL};

            // Just before we execv the hpsh binary, we set user execution user/group if specified in hp config.
            // (Must set gid before setting uid)
            if (!conf::cfg.hpsh.run_as.empty() && (setgid(conf::cfg.hpsh.run_as.gid) == -1 || setuid(conf::cfg.hpsh.run_as.uid) == -1))
            {
                std::cerr << errno << ": Hpsh process setgid/uid failed."
                          << "\n";
                exit(1);
            }

            execv(argv[0], argv);

            std::cerr << errno << ": Error executing hpsh."
                      << "\n";

            close(ctx.control_fds[0]);
            exit(1);
        }

        ctx.is_initialized = true;

        LOG_INFO << "Hpsh handler started.";

        return 0;
    }

    void deinit()
    {
        // This is not initialized if disabled in config.
        if (!conf::cfg.hpsh.enabled)
            return;

        ctx.is_shutting_down = true;

        if (ctx.hpsh_pid > 0)
            send_terminate_message();

        // Joining consensus processing thread.
        if (ctx.watcher_thread.joinable())
            ctx.watcher_thread.join();

        // close sockets.
        close(ctx.control_fds[0]);
        for (const auto &command : ctx.commands)
        {
            close(command.child_fds[0]);
            close(command.child_fds[1]);
        }

        if (ctx.hpsh_pid > 0)
        {
            // Check if the hpsh has exited voluntarily.
            if (check_hpsh_exited(false) == 0)
            {
                // Issue kill signal to kill the hpsh process.
                kill(ctx.hpsh_pid, SIGKILL);
                check_hpsh_exited(true); // Blocking wait until exit.
            }
        }

        LOG_INFO << "Hpsh handler stopped.";
    }

    int check_hpsh_exited(const bool block)
    {
        int scstatus = 0;
        const int wait_res = waitpid(ctx.hpsh_pid, &scstatus, block ? 0 : WNOHANG);

        if (wait_res == 0) // Child still running.
        {
            return 0;
        }
        if (wait_res == -1)
        {
            LOG_ERROR << errno << ": Hpsh process waitpid error. pid:" << ctx.hpsh_pid;
            ctx.hpsh_pid = 0;
            return -1;
        }
        else // Child has exited
        {
            ctx.hpsh_pid = 0;

            if (WIFEXITED(scstatus))
            {
                LOG_DEBUG << "Hpsh process ended normally.";
                return 1;
            }
            else
            {
                LOG_WARNING << "Hpsh process ended prematurely. Exit code " << WEXITSTATUS(scstatus);
                return -1;
            }
        }
    }

    int send_terminate_message()
    {
        return (write(ctx.control_fds[1], HPSH_CTR_TERMINATE, 10) < 0) ? -1 : 0;
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
                close(itr->child_fds[1]);
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

        // Send the hpsh request header.
        if (write(ctx.control_fds[1], HPSH_CTR_SH, 3) < 0)
        {
            LOG_ERROR << errno << ": Error writing header message to control fd.";
            return -1;
        }

        // Create a socket pair to communicate for the hpsh request.
        int child_fds[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, child_fds) == -1)
        {
            LOG_ERROR << errno << ": Error initializing socket pair.";
            return -1;
        }

        // Prepare and send the child socket file descriptor with scm rights.
        struct msghdr msg = {0};
        struct cmsghdr *cmsg;
        char iobuf[1];
        struct iovec io = {
            .iov_base = iobuf,
            .iov_len = sizeof(iobuf)};
        union
        { /* Ancillary data buffer, wrapped in a union
             in order to ensure it is suitably aligned */
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } u;

        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof(u.buf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), child_fds, sizeof(int));

        if (sendmsg(ctx.control_fds[1], &msg, 0) < 0)
        {
            LOG_ERROR << errno << ": Error writing to control fd.";
            close(child_fds[0]);
            close(child_fds[1]);
            return -1;
        }

        // Write the request message to the child socket.
        if (write(child_fds[1], message.data(), message.size()) < 0)
        {
            LOG_ERROR << errno << ": Error writing to child fd.";
            close(child_fds[0]);
            close(child_fds[1]);
            return -1;
        }

        // Close the child end of the socket.
        close(child_fds[0]);

        // Add the command to the context.
        {
            std::scoped_lock lock(ctx.command_mutex);
            ctx.commands.push_back(command_context{std::string(id), std::string(user_pubkey), {child_fds[0], child_fds[1]}});
        }

        return 0;
    }

    void response_watcher()
    {
        util::mask_signal();

        while (!ctx.is_shutting_down)
        {
            if (ctx.commands.size() > 0)
            {
                std::scoped_lock<std::mutex> lock(ctx.command_mutex);

                auto itr = ctx.commands.begin();
                while (itr != ctx.commands.end())
                {
                    if (ctx.is_shutting_down)
                        break;

                    struct pollfd pfd;
                    pfd.fd = itr->child_fds[1];
                    pfd.events = POLLIN;

                    // If child fd has data to read handle them.
                    if (poll(&pfd, 1, POLL_TIMEOUT) == -1)
                    {
                        LOG_ERROR << errno << ": Error in poll";
                        continue;
                    }
                    else if (pfd.revents & POLLIN)
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
                                std::vector<uint8_t> msg;
                                parser.create_hpsh_response_container(msg, itr->id, response);
                                user.session.send(msg);
                                response.clear();
                            }
                        }
                        else if (res == -1)
                        {
                            LOG_ERROR << errno << ": Error reading from fd";
                        }
                    }

                    itr++;
                }
            }
            util::sleep(100);
        }
    }
}