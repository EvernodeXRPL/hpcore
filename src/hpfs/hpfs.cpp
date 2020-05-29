#include "hpfs.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace hpfs
{
    pid_t merge_pid = 0;

    int init()
    {
        int res = start_hpfs_process("merge");
        if (res > 0)
            merge_pid = res;
        else
            return -1;

        return 0;
    }

    void deinit()
    {
        if (merge_pid > 0)
            kill(merge_pid, SIGINT); // Kill hpfs merge process.
    }

    int start_hpfs_process(const char *mode, const char *mount_dir)
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.

            // Wait for some time and check if the process is still running properly.
            util::sleep(20);
            int pid_status;
            waitpid(pid, &pid_status, WNOHANG);
            if (WIFEXITED(pid_status)) // This means process has exited.
                return -1;
        }
        else if (pid == 0)
        {
            // hpfs process.

            // Fill process args.
            char *execv_args[] = {
                conf::ctx.hpfs_exe_path.data(),
                (char *)mode, // hpfs mode: merge | rw | ro
                conf::ctx.state_dir.data(),
                (char *)mount_dir,
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERR << errno << ": hpfs process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERR << errno << ": fork() failed when starting hpfs process.";
            return -1;
        }

        return pid;
    }
} // namespace hpfs