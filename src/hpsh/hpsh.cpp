#include "../conf.hpp"
#include "../util/util.hpp"

namespace hpsh
{
    pid_t hpsh_pid;
    static int fd1[2];
    static int fd2[2];

    int deinit()
    {
        //kill(hpsh_pid, SIGTERM);
        close(fd1[0]);
        close(fd1[1]);
        close(fd2[0]);
        close(fd1[1]);

        LOG_INFO << "HPSH stopped.";

        return 0;
    }
    int init()
    {
        LOG_INFO << "Initializing HPSH";

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd1) == -1 || socketpair(AF_UNIX, SOCK_STREAM, 0, fd2) == -1)
        {
            return -1;
        }

        pid_t pid = fork();
        if (pid == -1)
        {
            return -1;
        }

        if (pid == 0)
        {
            hpsh_pid = getpid();
            char cfd1[10], cfd2[10];
            snprintf(cfd1, 10, "%d", fd1[0]);
            snprintf(cfd2, 10, "%d", fd2[1]);

            char *argv[] = {const_cast<char *>(conf::ctx.hpsh_exe_path.c_str()), (char *)("-s1"), cfd1, (char *)("-s2"), cfd2, NULL};
            LOG_DEBUG << "Starting HPSH Executable";
            execv(argv[0], argv);
            LOG_DEBUG << "Failed to execute hpsh";
            exit(EXIT_FAILURE);
        }
        else
        {
            close(fd1[0]);
            close(fd2[1]);

            return 0;
        }
    }

    std::string serve(const char *message)
    {
        char buffer[1024];

        ssize_t bytes_written = write(fd1[1], message, strlen(message));
        if (bytes_written == -1) {
            perror("Error when writing to HPSH socket");
        }

        LOG_DEBUG << "\nMessage sent from hpcore: " << message;

        while (true)
        {
            int bytesRead;
            bytesRead = read(fd2[0], buffer, sizeof(buffer));
            if (bytesRead < 0)
            {
                // Handle read error
                perror("read");
                return "error when reading";
            }


            buffer[bytesRead] = '\0'; // Null-terminate the buffer

            LOG_DEBUG << "\nMessage received in hpcore: " << buffer;
            if(bytesRead<1024){
                break;
            }
            
        }
        return buffer;
    }
}