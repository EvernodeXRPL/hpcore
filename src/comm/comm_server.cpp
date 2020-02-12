#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include "comm_server.hpp"
#include "comm_session.hpp"
#include "comm_session_handler.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace comm
{

int comm_server::start(const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type)
{
    int socket_fd = open_domain_socket(domain_socket_name);
    if (socket_fd > 0)
    {
        domain_sock_listener_thread = std::thread([&] { listen_domain_socket(socket_fd, session_type); });
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

    // Set non-blocking behaviour.
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

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

    return fd;
}

void comm_server::listen_domain_socket(const int socket_fd, const SESSION_TYPE session_type)
{
    const short poll_events = POLLIN | POLLHUP;
    std::unordered_map<int, comm_session> clients;

    while (true)
    {
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
            return;
        }
        else if (client_fd > 0)
        {
            // New client connected.
            comm_session session(client_fd, session_type);
            session.flags.set(SESSION_FLAG::INBOUND);
            session.on_connect();
            if (!session.flags[SESSION_FLAG::CLOSED])
                clients.emplace(client_fd, std::move(session));
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
                    ioctl(fd, FIONREAD, &available_bytes);

                    char buf[available_bytes];
                    const int read_len = read(fd, buf, available_bytes);
                    
                    if (read_len > 0)
                        session.on_message(buf);
                    else if (read_len == -1)
                        is_disconnect = true;
                }
                else if (result & POLLHUP)
                {
                    is_disconnect = true;
                }

                if (is_disconnect)
                {
                    session.close();
                    close(fd);
                    clients.erase(fd);
                    LOG_DBG << "Client fd " << fd << " disconnected from domain socket.";
                }
            }
        }
    }

    return;
}

int comm_server::start_websocketd_process(const uint16_t port, const char *domain_socket_name)
{
    const pid_t pid = fork();

    if (pid > 0)
    {
        // HotPocket process.
        websocketd_pid = pid;
    }
    else if (pid == 0)
    {
        // Websocketd process.

        // Fill process args.
        char port[] = "--port";
        char nc[] = "nc";
        char nc_arg[] = "-U";
        std::string sock_name = domain_socket_name;

        char *execv_args[6];
        execv_args[0] = conf::ctx.websocketd_exe_path.data();
        execv_args[1] = port;
        execv_args[2] = std::to_string(conf::cfg.pubport).data();
        execv_args[3] = nc;
        execv_args[4] = nc_arg;
        execv_args[5] = sock_name.data();

        int ret = execv(execv_args[0], execv_args);
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

} // namespace comm