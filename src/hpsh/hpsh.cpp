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

        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ctx.control_fds) == -1)
        {
            LOG_ERROR << errno << ": Error initializing socket pair.";
            return -1;
        }

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
            close(ctx.control_fds[0]);

            ctx.watcher_thread = std::thread(response_watcher);
        }
        else if (ctx.hpsh_pid == 0)
        {
            util::fork_detach();

            close(ctx.control_fds[1]);

            std::string fd_str;
            fd_str.resize(10);
            snprintf(fd_str.data(), sizeof(fd_str), "%d", ctx.control_fds[0]);

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

    int execute(std::string_view id, std::string_view pubkey, std::string_view message)
    {
        if (ctx.is_shutting_down)
            return -1;

        if (write(ctx.control_fds[1], HPSH_CTR_SH, 3) < 0)
        {
            LOG_ERROR << errno << ": Error writing header message to control fd.";
            return -1;
        }

        int child_fds[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, child_fds) == -1)
        {
            LOG_ERROR << errno << ": Error initializing socket pair.";
            return -1;
        }

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

        if (write(child_fds[1], message.data(), sizeof(message)) < 0)
        {
            LOG_ERROR << errno << ": Error writing to child fd.";
            close(child_fds[0]);
            close(child_fds[1]);
            return -1;
        }

        {
            std::scoped_lock lock(ctx.command_mutex);
            ctx.commands.push_back(command_context{std::string(id), std::string(pubkey), {child_fds[0], child_fds[1]}, std::string(), false});
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
                auto itr = ctx.commands.begin();
                while (itr != ctx.commands.end())
                {
                    if (ctx.is_shutting_down)
                        break;

                    struct pollfd pfd;
                    pfd.fd = itr->child_fds[1];
                    pfd.events = POLLIN;

                    if (poll(&pfd, 1, POLL_TIMEOUT) == -1)
                    {
                        LOG_ERROR << errno << ": Error in poll";
                        continue;
                    }
                    else if (pfd.revents & POLLIN)
                    {
                        itr->response.resize(READ_BUFFER_SIZE);
                        const int res = read(pfd.fd, itr->response.data(), READ_BUFFER_SIZE);

                        if (res > 0)
                            itr->response.resize(res); // Resize back to the actual bytes read.
                        else if (res == -1)
                        {
                            // Assuming that EPIPE or ECONNRESET resulted from contract termination, consider this as a neutral read.
                            if (errno == EPIPE || errno == ECONNRESET)
                                itr->read_completed = true;
                            else
                                LOG_ERROR << errno << ": Error reading from fd";
                        }
                    }
                    else
                    {
                        itr->read_completed = true;
                    }

                    // Send command back to user;
                    if (itr->read_completed)
                    {
                        {
                            std::scoped_lock<std::mutex> lock(usr::ctx.users_mutex);

                            // Find the user session by user pubkey.
                            const auto user_itr = usr::ctx.users.find(itr->pubkey);
                            if (user_itr != usr::ctx.users.end()) // match found
                            {
                                const usr::connected_user &user = user_itr->second;
                                msg::usrmsg::usrmsg_parser parser(user.protocol);
                                std::vector<uint8_t> msg;
                                parser.create_hpsh_response_container(msg, itr->id, itr->response);
                                user.session.send(msg);
                            }
                        }
                        {
                            std::scoped_lock<std::mutex> lock(ctx.command_mutex);
                            itr = ctx.commands.erase(itr);
                        }
                    }
                    else
                    {
                        itr++;
                    }
                }
            }
            else
            {
                util::sleep(1000);
            }
        }
    }
}