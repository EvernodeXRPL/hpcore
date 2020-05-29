#include "hpfs.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace hpfs
{
    pid_t merge_pid = 0;

    int init()
    {
        LOG_INFO << "Starting hpfs merge process...";
        int res = start_hpfs_process("merge", NULL);
        if (res > 0)
            merge_pid = res;
        else
            return -1;

        LOG_INFO << "Started hpfs merge process.";
        return 0;
    }

    void deinit()
    {
        LOG_INFO << "Stopping hpfs merge process...";
        if (merge_pid > 0 && util::kill_process(merge_pid) == 0)
            LOG_INFO << "Stopped hpfs merge process.";
    }

    int start_hpfs_process(const char *mode, const char *mount_dir)
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.

            // Wait until hpfs is initialized properly.
            bool hpfs_initialized = false;
            uint8_t retry_count = 0;
            do
            {
                util::sleep(20);

                // Check if hpfs process is still running.
                if (kill(pid, 0) == -1)
                    break;

                // If hpfs is launched with fuse mount we check for the root hash
                // virtual file in hpfs.
                if (mount_dir != NULL)
                {
                    const std::string hash_file = std::string(mount_dir).append("/::hpfs.hmap.hash");
                    struct stat st;
                    hpfs_initialized = (stat(hash_file.c_str(), &st) == 0);
                }
                else
                {
                    hpfs_initialized = true;
                }

            } while (!hpfs_initialized && ++retry_count < 100);

            // Kill the process if hpfs couldn't be initialized after the wait period.
            if (!hpfs_initialized)
            {
                LOG_ERR << "Couldn't initialize hpfs.";
                kill(pid, SIGINT);
                return -1;
            }
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