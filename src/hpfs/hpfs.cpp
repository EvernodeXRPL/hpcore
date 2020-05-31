#include "hpfs.hpp"
#include "h32.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace hpfs
{
    pid_t merge_pid = 0;

    int init()
    {
        LOG_INFO << "Starting hpfs merge process...";
        if (start_merge_process() == -1)
            return -1;

        LOG_INFO << "Started hpfs merge process. pid:" << merge_pid;
        return 0;
    }

    void deinit()
    {
        LOG_INFO << "Stopping hpfs merge process... pid:" << merge_pid;
        if (merge_pid > 0 && util::kill_process(merge_pid) == 0)
            LOG_INFO << "Stopped hpfs merge process.";
    }

    int start_merge_process()
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.
            // Check if process is still running.
            util::sleep(20);
            if (kill(pid, 0) == -1)
                return -1;

            merge_pid = pid;
        }
        else if (pid == 0)
        {
            // hpfs process.
            // Fill process args.
            char *execv_args[] = {
                conf::ctx.hpfs_exe_path.data(),
                (char *)"merge",
                conf::ctx.state_dir.data(),
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERR << errno << ": hpfs merge process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERR << errno << ": fork() failed when starting hpfs merge process.";
            return -1;
        }

        return 0;
    }

    int start_fs_session(pid_t &session_pid, std::string &mount_dir,
                         const char *mode, const bool hash_map_enabled)
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.

            // If the mound dir is not specified, assign a mount dir based on hpfs process id.
            if (mount_dir.empty())
                mount_dir = std::string(conf::ctx.state_dir)
                                .append("/")
                                .append(std::to_string(pid));

            // Wait until hpfs is initialized properly.
            bool hpfs_initialized = false;
            uint8_t retry_count = 0;
            do
            {
                util::sleep(20);

                // Check if process is still running.
                if (kill(pid, 0) == -1)
                    break;

                // If hpfs is initialized, the inode no. of the mounted root dir is always 1.
                struct stat st;
                hpfs_initialized = (stat(mount_dir.c_str(), &st) == 0 && st.st_ino == 1);

            } while (!hpfs_initialized && ++retry_count < 100);

            // Kill the process if hpfs couldn't be initialized after the wait period.
            if (!hpfs_initialized)
            {
                LOG_ERR << "Couldn't initialize hpfs session.";
                kill(pid, SIGKILL);
                return -1;
            }

            session_pid = pid;
        }
        else if (pid == 0)
        {
            // hpfs process.

            // If the mound dir is not specified, assign a mount dir based on hpfs process id.
            const pid_t self_pid = getpid();
            if (mount_dir.empty())
                mount_dir = std::string(conf::ctx.state_dir)
                                .append("/")
                                .append(std::to_string(self_pid));

            // Fill process args.
            char *execv_args[] = {
                conf::ctx.hpfs_exe_path.data(),
                (char *)mode, // hpfs mode: rw | ro
                conf::ctx.state_dir.data(),
                mount_dir.data(),
                (char *)(hash_map_enabled ? "hmap=true" : "hmap-false"),
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERR << errno << ": hpfs session process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERR << errno << ": fork() failed when starting hpfs session process.";
            return -1;
        }

        return 0;
    }

    int get_root_hash(h32 &hash)
    {
        pid_t pid;
        std::string mount_dir;
        if (start_fs_session(pid, mount_dir, "ro", true) == -1 ||
            get_hash(hash, mount_dir, "/") == -1 ||
            kill(pid, SIGINT) == -1)
            return -1;

        return 0;
    }

    int get_hash(h32 &hash, const std::string_view mount_dir, const std::string_view vpath)
    {
        std::string path = std::string(mount_dir).append(vpath).append("::hpfs.hmap.hash");
        int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERR << errno << ": Error opening hash file.";
            return -1;
        }
        int res = read(fd, &hash, sizeof(h32));
        close(fd);
        if (res == -1)
        {
            LOG_ERR << errno << ": Error reading hash file.";
            return -1;
        }
        return 0;
    }

} // namespace hpfs