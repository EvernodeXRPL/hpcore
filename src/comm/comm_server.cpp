#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include "comm_server.hpp"
#include "comm_client.hpp"
#include "comm_session.hpp"
#include "comm_session_handler.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../bill/corebill.h"

namespace comm
{

    int comm_server::start(
        const uint16_t port, const char *domain_socket_name, const SESSION_TYPE session_type, const bool is_binary, const bool use_size_header,
        const uint64_t (&metric_thresholds)[4], const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size)
    {
        int accept_fd = open_domain_socket(domain_socket_name);
        if (accept_fd > 0)
        {
            watchdog_thread = std::thread(
                &comm_server::connection_watchdog, this, accept_fd, session_type, is_binary,
                std::ref(metric_thresholds), req_known_remotes, max_msg_size);
            return start_websocketd_process(port, domain_socket_name, is_binary,
                                            use_size_header, max_msg_size);
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
        // We do this so the accept() call returns immediately without blocking the listening thread.
        int flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        return fd; // This is the fd we should call accept() on.
    }

    void comm_server::connection_watchdog(
        const int accept_fd, const SESSION_TYPE session_type, const bool is_binary,
        const uint64_t (&metric_thresholds)[4], const std::set<conf::ip_port_pair> &req_known_remotes, const uint64_t max_msg_size)
    {
        util::mask_signal();

        // Map with read fd to connected session mappings.
        std::unordered_map<int, comm_session> sessions;
        // Map with read fd to connected comm client mappings.
        std::unordered_map<int, comm_client> outbound_clients;

        // Counter to track when to initiate outbound client connections.
        int16_t loop_counter = -1;

        while (true)
        {
            if (should_stop_listening)
                break;

            // Prepare poll fd list.
            const size_t fd_count = sessions.size() + 1; //+1 for the inclusion of accept_fd
            pollfd pollfds[fd_count];
            if (poll_fds(pollfds, accept_fd, sessions) == -1)
            {
                util::sleep(10);
                continue;
            }

            util::sleep(10);

            // Accept any new incoming connection if available.
            check_for_new_connection(sessions, accept_fd, session_type, is_binary, metric_thresholds);

            if (!req_known_remotes.empty())
            {
                // Restore any missing outbound connections every 500 iterations (including the first iteration).
                if (loop_counter == -1 || loop_counter == 500)
                {
                    loop_counter = 0;
                    maintain_known_connections(sessions, outbound_clients, req_known_remotes, session_type, is_binary, max_msg_size, metric_thresholds);
                }
                loop_counter++;
            }

            const size_t sessions_count = sessions.size();

            // Loop through all fds and read any data.
            for (size_t i = 1; i <= sessions_count; i++)
            {
                const short result = pollfds[i].revents;
                const int fd = pollfds[i].fd;

                const auto iter = sessions.find(fd);
                if (iter != sessions.end())
                {
                    comm_session &session = iter->second;
                    bool should_disconnect = (session.state == SESSION_STATE::CLOSED);

                    if (!should_disconnect)
                    {
                        if (result & POLLIN)
                            should_disconnect = (session.attempt_read(max_msg_size) == -1);

                        if (result & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL))
                            should_disconnect = true;
                    }

                    if (should_disconnect)
                    {
                        // If this is an outbound session, cleanup the corresponding comm client as well.
                        if (!session.is_inbound)
                        {
                            const auto client_itr = outbound_clients.find(fd);
                            client_itr->second.stop();
                            outbound_clients.erase(client_itr);
                        }

                        session.close();
                        sessions.erase(fd);
                    }
                }
            }
        }

        // If we reach this point that means we are shutting down.

        // Close all sessions and clients
        for (auto &[fd, session] : sessions)
            session.close(false);
        for (auto &[fd, client] : outbound_clients)
            client.stop();

        LOG_INFO << (session_type == SESSION_TYPE::USER ? "User" : "Peer") << " listener stopped.";
    }

    int comm_server::poll_fds(pollfd *pollfds, const int accept_fd, const std::unordered_map<int, comm_session> &sessions)
    {
        const short poll_events = POLLIN | POLLRDHUP;
        pollfds[0].fd = accept_fd;

        auto iter = sessions.begin();
        for (size_t i = 1; i <= sessions.size(); i++)
        {
            pollfds[i].fd = iter->first;
            pollfds[i].events = poll_events;
            iter++;
        }

        if (poll(pollfds, sessions.size() + 1, 10) == -1) //10ms timeout
        {
            LOG_ERR << errno << ": Poll failed.";
            return -1;
        }

        return 0;
    }

    void comm_server::check_for_new_connection(
        std::unordered_map<int, comm_session> &sessions, const int accept_fd,
        const SESSION_TYPE session_type, const bool is_binary, const uint64_t (&metric_thresholds)[4])
    {
        // Accept new client connection (if available)
        int client_fd = accept(accept_fd, NULL, NULL);
        if (client_fd == -1 && errno != EAGAIN)
        {
            LOG_ERR << errno << ": Domain socket accept error";
        }
        else if (client_fd > 0)
        {
            // New client connected.
            const std::string ip = get_cgi_ip(client_fd);
            if (!ip.empty())
            {
                if (corebill::is_banned(ip))
                {
                    LOG_DBG << "Dropping connection for banned host " << ip;
                    close(client_fd);
                }
                else
                {
                    comm_session session(ip, client_fd, client_fd, session_type, is_binary, true, metric_thresholds);
                    if (session.on_connect() == 0)
                        sessions.try_emplace(client_fd, std::move(session));
                }
            }
            else
            {
                close(client_fd);
                LOG_ERR << "Closed bad client socket: " << client_fd;
            }
        }
    }

    void comm_server::maintain_known_connections(
        std::unordered_map<int, comm_session> &sessions, std::unordered_map<int, comm_client> &outbound_clients,
        const std::set<conf::ip_port_pair> &req_known_remotes, const SESSION_TYPE session_type, const bool is_binary,
        const uint64_t max_msg_size, const uint64_t (&metric_thresholds)[4])
    {
        // Find already connected known remote parties list
        std::set<conf::ip_port_pair> known_remotes;
        for (const auto &[fd, session] : sessions)
        {
            if (session.state != SESSION_STATE::CLOSED && !session.known_ipport.first.empty())
                known_remotes.emplace(session.known_ipport);
        }

        for (const auto &ipport : req_known_remotes)
        {
            if (should_stop_listening)
                break;

            // Check if we are already connected to this remote party.
            if (known_remotes.find(ipport) != known_remotes.end())
                continue;

            std::string_view host = ipport.first;
            const uint16_t port = ipport.second;
            LOG_DBG << "Trying to connect " << host << ":" << std::to_string(port);

            comm::comm_client client;
            if (client.start(host, port, metric_thresholds, conf::cfg.peermaxsize) == -1)
            {
                LOG_ERR << "Outbound connection attempt failed: " << host << ":" << std::to_string(port);
            }
            else
            {
                comm::comm_session session(host, client.read_fd, client.write_fd, comm::SESSION_TYPE::PEER, is_binary, false, metric_thresholds);
                session.known_ipport = ipport;
                if (session.on_connect() == 0)
                {
                    sessions.try_emplace(client.read_fd, std::move(session));
                    outbound_clients.emplace(client.read_fd, std::move(client));
                    known_remotes.emplace(ipport);
                }
            }
        }
    }

    int comm_server::start_websocketd_process(
        const uint16_t port, const char *domain_socket_name,
        const bool is_binary, const bool use_size_header, const uint64_t max_msg_size)
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

            // Close the child reading end of the pipe in the parent
            if (firewall_out > 0)
                close(firewall_pipe[0]);

            // Wait for some time and check if websocketd is still running properly.
            util::sleep(20);
            if (kill(pid, 0) == -1)
                return -1;

            websocketd_pid = pid;
        }
        else if (pid == 0)
        {
            // Websocketd process.
            util::unmask_signal();

            // We are using websocketd forked repo: https://github.com/codetsunami/websocketd

            if (firewall_out > 0)
            {
                // Close parent writing end of the pipe in the child
                close(firewall_pipe[1]);
                // Override stdin in the child's file table
                dup2(firewall_pipe[0], 0);
            }

            std::vector<std::string> args_vec;
            args_vec.reserve(16);

            // Fill process args.
            args_vec.push_back(conf::ctx.websocketd_exe_path);
            args_vec.push_back("--port");
            args_vec.push_back(std::to_string(port));
            args_vec.push_back("--ssl");
            args_vec.push_back("--sslcert");
            args_vec.push_back(conf::ctx.tls_cert_file);
            args_vec.push_back("--sslkey");
            args_vec.push_back(conf::ctx.tls_key_file);
            args_vec.push_back(is_binary ? "--binary=true" : "--binary=false");
            args_vec.push_back(use_size_header ? "--sizeheader=true" : "--sizeheader=false");

            if (max_msg_size > 0)
                args_vec.push_back(std::string("--maxframe=").append(std::to_string(max_msg_size)));

            args_vec.push_back("--loglevel=error");
            args_vec.push_back("nc"); // netcat (OpenBSD) is used for domain socket redirection.
            args_vec.push_back("-U"); // Use UNIX domain socket
            args_vec.push_back(domain_socket_name);

            char *execv_args[args_vec.size()];
            int idx = 0;
            for (std::string &arg : args_vec)
                execv_args[idx++] = arg.data();
            execv_args[idx] = NULL;

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERR << errno << ": websocketd process execv failed.";
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

    /**
 * If the fd supplied was produced by accept()ing unix domain socket connection
 * the process at the other end is inspected for CGI environment variables
 * and the REMOTE_ADDR variable is returned as std::string, otherwise empty string
 */
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
        watchdog_thread.join();

        if (websocketd_pid > 0)
            util::kill_process(websocketd_pid, false); // Kill websocketd.
    }

} // namespace comm
