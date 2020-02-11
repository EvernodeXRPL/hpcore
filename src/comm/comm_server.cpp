#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include "comm_server.hpp"
#include "comm_session.hpp"
#include "comm_session_handler.hpp"
#include "../util.hpp"

namespace comm
{

int comm_server::start(const uint16_t port, const char *domain_socket_name, comm_session_handler &sess_handler)
{
    int socket_fd = open_domain_socket(domain_socket_name);
    if (socket_fd > 0)
    {
        domain_sock_reader_thread = std::thread([&] { read_client_sockets(); });
        domain_sock_listener_thread = std::thread([&] { listen_domain_socket(socket_fd, sess_handler); });
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

    return fd;
}

void comm_server::listen_domain_socket(const int socket_fd, comm_session_handler &sess_handler)
{
    while (true)
    {
        int client = accept(socket_fd, NULL, NULL);
        if (client == -1)
        {
            LOG_ERR << errno << ": Domain socket accept error";
            continue;
        }

        comm_session session(std::to_string(client), sess_handler);
        session.on_connect();

        domain_sock_clients.emplace(client, std::move(session));
    }

    return;
}

void comm_server::read_client_sockets()
{
    const short poll_events = POLLIN | POLLHUP;

    while (true)
    {
        // Prepare poll fd list.
        const size_t count = domain_sock_clients.size();
        pollfd pollfds[count];
        auto iter = domain_sock_clients.begin();

        for (size_t i = 0; i < count; i++)
        {
            pollfds[i].fd = iter->first;
            pollfds[i].events = poll_events;
            iter++;
        }

        if (poll(pollfds, count, 10) == -1)
        {
            LOG_ERR << errno << ": Poll failed.";
            util::sleep(10);
        }

        for (size_t i = 0; i < count; i++)
        {
            const short result = pollfds[i].revents;
            const int fd = pollfds[i].fd;
            comm_session &session = domain_sock_clients[fd];
            bool is_disconnect = false;

            if (result & POLLIN)
            {
                int available_bytes;
                ioctl(fd, FIONREAD, &count);

                char buf[available_bytes];
                const int read_len = read(fd, buf, available_bytes);
                if (read_len > 0)
                {
                    write(fd, "got some bytes from you:\n", strlen("got some bytes from you:\n"));
                    write(fd, buf, read_len);

                    session.on_message(buf);
                }
                else if (read_len == -1)
                {
                    is_disconnect = true;
                }
            }
            else if (result & POLLHUP)
            {
                is_disconnect = true;
            }

            if (is_disconnect)
            {
                session.on_close();
                close(fd);
                domain_sock_clients.erase(fd);
                LOG_DBG << "Client fd " << fd << " disconnected from domain socket.";
            }
        }
    }
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