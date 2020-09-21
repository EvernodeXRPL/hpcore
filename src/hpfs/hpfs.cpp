#include "hpfs.hpp"
#include "h32.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace hpfs
{
    constexpr const char *HPFS_TRACE_ARG_ERROR = "trace=error";
    constexpr const char *HPFS_TRACE_ARG_DEBUG = "trace=debug";
    constexpr uint16_t INIT_CHECK_INTERVAL = 20;

    pid_t merge_pid = 0;
    bool init_success = false;
    const char *active_hpfs_trace_arg;

    int init()
    {
        conf::LOG_SEVERITY log_severity = conf::get_log_severity_type(conf::cfg.loglevel);
        active_hpfs_trace_arg = (log_severity == conf::LOG_SEVERITY::DEBUG ? HPFS_TRACE_ARG_DEBUG : HPFS_TRACE_ARG_ERROR);

        LOG_INFO << "Starting hpfs merge process...";
        if (start_merge_process() == -1)
            return -1;

        LOG_INFO << "Started hpfs merge process. pid:" << merge_pid;
        init_success = true;
        return 0;
    }

    void deinit()
    {
        if (init_success)
        {
            LOG_INFO << "Stopping hpfs merge process... pid:" << merge_pid;
            if (merge_pid > 0 && util::kill_process(merge_pid, true) == 0)
                LOG_INFO << "Stopped hpfs merge process.";
        }
    }

    int start_merge_process()
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.
            util::sleep(INIT_CHECK_INTERVAL);

            // Check if hpfs process is still running.
            // Sending signal 0 to test whether process exist.
            if (util::kill_process(pid, false, 0) == -1)
                return -1;

            merge_pid = pid;
        }
        else if (pid == 0)
        {
            // hpfs process.
            util::unmask_signal();

            // Fill process args.
            char *execv_args[] = {
                conf::ctx.hpfs_exe_path.data(),
                (char *)"merge",
                conf::ctx.state_dir.data(),
                (char *)active_hpfs_trace_arg,
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERROR << errno << ": hpfs merge process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting hpfs merge process.";
            return -1;
        }

        return 0;
    }

    int start_fs_session(pid_t &session_pid, std::string &mount_dir,
                         const char *mode, const bool hash_map_enabled, const uint16_t timeout)
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            // HotPocket process.
            LOG_DEBUG << "Starting hpfs " << mode << " session...";

            // If the mount dir is not specified, assign a mount dir based on hpfs process id.
            if (mount_dir.empty())
                mount_dir = std::string(conf::ctx.state_dir)
                                .append("/")
                                .append(std::to_string(pid));

            // The path used for checking whether hpfs has finished initializing.
            const std::string check_path = hash_map_enabled
                                               ? std::string(mount_dir).append("/::hpfs.hmap.hash")
                                               : mount_dir;

            // Wait until hpfs is initialized properly.
            const uint16_t max_retries = timeout / INIT_CHECK_INTERVAL;
            bool hpfs_initialized = false;
            uint16_t retry_count = 0;
            do
            {
                util::sleep(INIT_CHECK_INTERVAL);

                // Check if hpfs process is still running.
                // Sending signal 0 to test whether process exist.
                if (util::kill_process(pid, false, 0) == -1)
                {
                    LOG_ERROR << "hpfs process " << pid << " has stopped.";
                    break;
                }

                // If hash map is enabled we check whether stat succeeds on the root hash.
                // If not, we check whether the inode no. of the mounted root dir is 1.
                struct stat st;
                hpfs_initialized = (stat(check_path.c_str(), &st) == 0 &&
                                    (hash_map_enabled || st.st_ino == 1));

                // The only error that warrants a retry is ENOENT (no entry).
                // When hpfs is fully initialized we should receive some file from check_path.
                if (!hpfs_initialized && errno != ENOENT)
                {
                    LOG_ERROR << errno << ": Error in checking hpfs status.";
                    break;
                }

            } while (!hpfs_initialized && ++retry_count <= max_retries);

            // Kill the process if hpfs couldn't be initialized after the wait period.
            if (!hpfs_initialized)
            {
                LOG_ERROR << "Couldn't initialize hpfs session.";
                util::kill_process(pid, true);
                return -1;
            }

            session_pid = pid;
        }
        else if (pid == 0)
        {
            // hpfs process.
            util::unmask_signal();

            // If the mount dir is not specified, assign a mount dir based on hpfs process id.
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
                (char *)(hash_map_enabled ? "hmap=true" : "hmap=false"),
                (char *)active_hpfs_trace_arg,
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            LOG_ERROR << errno << ": hpfs session process execv failed.";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting hpfs session process.";
            return -1;
        }

        return 0;
    }

    int get_hash(h32 &hash, const std::string_view mount_dir, const std::string_view vpath)
    {
        const std::string path = std::string(mount_dir).append(vpath).append("::hpfs.hmap.hash");
        const int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening hash file.";
            return -1;
        }
        const int res = read(fd, &hash, sizeof(h32));
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash file.";
            return -1;
        }
        return 0;
    }

    int get_file_block_hashes(std::vector<h32> &hashes, const std::string_view mount_dir, const std::string_view vpath)
    {
        const std::string path = std::string(mount_dir).append(vpath).append("::hpfs.hmap.children");
        const int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1)
            return -1;

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error reading block hashes length.";
            return -1;
        }

        const int children_count = st.st_size / sizeof(h32);
        hashes.resize(children_count);

        const int res = read(fd, hashes.data(), st.st_size);
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash block hashes.";
            return -1;
        }
        return 0;
    }

    int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, const std::string_view mount_dir, const std::string_view dir_vpath)
    {
        const std::string path = std::string(mount_dir).append(dir_vpath).append("::hpfs.hmap.children");
        const int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening hash children nodes.";
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error reading hash children nodes length.";
            return -1;
        }

        const int children_count = st.st_size / sizeof(child_hash_node);
        hash_nodes.resize(children_count);

        const int res = read(fd, hash_nodes.data(), st.st_size);
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash children nodes.";
            return -1;
        }
        return 0;
    }

} // namespace hpfs