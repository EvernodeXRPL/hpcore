#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include "comm_server.hpp"
#include "comm_session.hpp"
#include "comm_session_handler.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../bill/corebill.h"

namespace comm
{

int comm_server::start(const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type, const SESSION_MODE mode, std::mutex &sessions_mutex)
{
    int socket_fd = open_domain_socket(domain_socket_name);
    if (socket_fd > 0)
    {
        domain_sock_listener_thread = std::thread(&comm_server::listen_domain_socket, this, socket_fd, session_type, mode, std::ref(sessions_mutex));
        return start_websocketd_process(port, domain_socket_name);
    }

    return -1;
}

int comm_server::open_domain_socket(const char *domain_socket_name)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        LOG_ERR << errno << ": Domain socket open error";
        return -1;
    }

    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    strncpy(addr.sun_path, domain_socket_name, sizeof(addr.sun_path) - 1);
    unlink(domain_socket_name);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        LOG_ERR << errno << ": Domain socket bind error";
        return -1;
    }

    if (listen(fd, 5) == -1)
    {
        LOG_ERR << errno << ": Domain socket listen error";
        return -1;
    }

    // Set non-blocking behaviour.
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

void comm_server::listen_domain_socket(const int socket_fd, const SESSION_TYPE session_type, const SESSION_MODE mode, std::mutex &sessions_mutex)
{
    const short poll_events = POLLIN | POLLRDHUP;
    std::unordered_map<int, comm_session> clients;

    while (true)
    {
        if (should_stop_listening)
        {
            // Close all fds.
            close(socket_fd);
            for (auto &[fd, session] : clients)
                session.close();

            return;
        }

        // Prepare poll fd list.
        const size_t fd_count = clients.size() + 1; //+1 for the inclusion of socket_fd
        pollfd pollfds[fd_count];

        pollfds[0].fd = socket_fd;

        auto iter = clients.begin();
        for (size_t i = 1; i < fd_count; i++)
        {
            pollfds[i].fd = iter->first;
            pollfds[i].events = poll_events;
            iter++;
        }

        if (poll(pollfds, fd_count, 10) == -1) //10ms timeout
        {
            LOG_ERR << errno << ": Poll failed.";
            util::sleep(10);
            continue;
        }

        // Accept new client connection (if available)
        int client_fd = accept(socket_fd, NULL, NULL);
        if (client_fd == -1 && errno != EAGAIN)
        {
            LOG_ERR << errno << ": Domain socket accept error";
        }
        else if (client_fd > 0)
        {
            // New client connected.
            const std::string ip = get_cgi_ip(client_fd);

            if (corebill::is_banned(ip))
            {
                LOG_DBG << "Dropping connection for banned host " << ip;
                close(client_fd);
            }
            else
            {
                comm_session session(ip, client_fd, session_type, mode);
                session.on_connect();

                // We check for 'closed' state here because corebill might close the connection immediately.
                if (!session.state == SESSION_STATE::CLOSED)
                {
                    std::lock_guard<std::mutex> lock(sessions_mutex);
                    clients.emplace(client_fd, std::move(session));
                }
            }
        }

        const size_t clients_count = clients.size();

        // Loop through all client fds and read any data.
        for (size_t i = 1; i <= clients_count; i++)
        {
            const short result = pollfds[i].revents;
            const int fd = pollfds[i].fd;

            const auto iter = clients.find(fd);
            if (iter != clients.end())
            {
                comm_session &session = iter->second;
                bool is_disconnect = false;

                if (result & POLLIN)
                {
                    int available_bytes;
                    if (ioctl(fd, FIONREAD, &available_bytes) == -1 || available_bytes == 0)
                    {
                        is_disconnect = true;
                    }
                    else if (available_bytes > 0)
                    {
                        // TODO: Here we need to introduce byte length prefix and wait until all bytes
                        // are available.

                        char buf[available_bytes];
                        const int read_len = read(fd, buf, available_bytes);

                        if (read_len > 0)
                            session.on_message(buf);
                        else if (read_len == -1)
                            is_disconnect = true;
                    }
                }

                if (result & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL))
                    is_disconnect = true;

                if (is_disconnect)
                {
                    session.close();
                    close(fd);
                    {
                        std::lock_guard<std::mutex> lock(sessions_mutex);
                        clients.erase(fd);
                    }
                }
            }
        }
    }

    return;
}

int comm_server::start_websocketd_process(const uint16_t port, const char *domain_socket_name)
{

    // setup pipe for firewall
    int firewall_pipe[2]; // parent to child pipe

    if (pipe(firewall_pipe))
    {
        LOG_ERR << errno << ": pipe() call failed for firewall";
    }
    else
    {
        firewall_out = firewall_pipe[1];
    }

    const pid_t pid = fork();

    if (pid > 0)
    {
        // HotPocket process.
        websocketd_pid = pid;

        // Close the child reading end of the pipe in the parent
        if (firewall_out > 0)
            close(firewall_pipe[0]);
    }
    else if (pid == 0)
    {
        // Websocketd process.

        if (firewall_out > 0)
        {
            // Close parent writing end of the pipe in the child
            close(firewall_pipe[1]);
            // Override stdin in the child's file table
            dup2(firewall_pipe[0], 0);
        }

        // Override stdout in the child's file table with /dev/null
        //        int null_fd = open("/dev/null", O_WRONLY);
        //        if (null_fd)
        //            dup2(null_fd, 1);

        // Fill process args.
        char *execv_args[] = {
            conf::ctx.websocketd_exe_path.data(),
            (char *)"--port",
            std::to_string(conf::cfg.pubport).data(),
            (char *)"--ssl",
            (char *)"--sslcert",
            conf::ctx.tls_cert_file.data(),
            (char *)"--sslkey",
            conf::ctx.tls_key_file.data(),
            (char *)"nc",
            (char *)"-U",
            (char *)domain_socket_name,
            NULL};

        const int ret = execv(execv_args[0], execv_args);
        LOG_ERR << errno << ": Contract process execv failed.";
        exit(1);
    }
    else
    {
        LOG_ERR << "fork() failed when starting websocketd process.";
        return -1;
    }

    return 0;
}

void comm_server::firewall_ban(std::string_view ip, const bool unban)
{
    if (firewall_out < 0)
        return;

    iovec iov[]{
        {(void *)(unban ? "r" : "a"), 1},
        {(void *)ip.data(), ip.length()}};
    writev(firewall_out, iov, 2);
}

std::string comm_server::get_cgi_ip(const int fd)
{
    socklen_t length;
    ucred uc;
    length = sizeof(struct ucred);

    // Ask the operating system for information about the other process
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &length) == -1)
    {
        LOG_ERR << errno << ": Could not retrieve PID from unix domain socket";
        return "";
    }

    // Open /proc/<pid>/environ for that process
    std::stringstream ss;
    ss << "/proc/" << uc.pid << "/environ";
    std::string fn = ss.str();

    const int envfd = open(fn.c_str(), O_RDONLY);
    if (!envfd)
    {
        LOG_ERR << errno << ": Could not open environ block for process on other end of unix domain socket PID=" << uc.pid;
        return "";
    }

    // Read environ block
    char envblock[0x7fff];
    const ssize_t bytes_read = read(envfd, envblock, 0x7fff); //0x7fff bytes is an operating system size limit for this block
    close(envfd);

    // Find the REMOTE_ADDR entry. Envrion block delimited by \0
    for (char *upto = envblock, *last = envblock; upto - envblock < bytes_read; ++upto)
    {
        if (*upto == '\0')
        {
            if (upto - last > 12 && strncmp(last, "REMOTE_ADDR=", 12) == 0)
                return std::string((const char *)(last + 12));
            last = upto + 1;
        }
    }

    LOG_ERR << "Could not find REMOTE_ADDR variable in /proc/" << uc.pid << "/environ";
    return "";
}

void comm_server::stop()
{
    should_stop_listening = true;
    util::sleep(100);             // Give some time to listening thread to gracefully exit.
    kill(websocketd_pid, SIGINT); // Kill websocketd.
}

} // namespace comm
