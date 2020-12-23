#include "hpfs.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../util/h32.hpp"

namespace hpfs
{
    constexpr const char *HPFS_TRACE_ARG_ERROR = "trace=error";
    constexpr const char *HPFS_TRACE_ARG_DEBUG = "trace=error";
    constexpr const char *HPFS_HMAP_HASH = "::hpfs.hmap.hash";
    constexpr const char *HPFS_HMAP_CHILDREN = "::hpfs.hmap.children";
    constexpr const char *HPFS_SESSION = "::hpfs.session";
    constexpr ino_t HPFS_ROOT_INO = 2;
    constexpr uint16_t INIT_CHECK_INTERVAL = 20;

    /**
     * Starts hpfs merge process.
     */
    int start_merge_process(pid_t &hpfs_pid)
    {
        const pid_t pid = fork();

        if (pid > 0)
        {
            LOG_DEBUG << "Starting hpfs merge process...";

            // HotPocket process.
            util::sleep(INIT_CHECK_INTERVAL);

            // Check if hpfs process is still running.
            // Sending signal 0 to test whether process exist.
            if (util::kill_process(pid, false, 0) == -1)
                return -1;

            hpfs_pid = pid;
            LOG_DEBUG << "hpfs merge process started. pid:" << hpfs_pid;
        }
        else if (pid == 0)
        {
            // hpfs process.
            util::fork_detach();

            const char *active_hpfs_trace_arg = (conf::cfg.log.loglevel_type == conf::LOG_SEVERITY::DEBUG ? HPFS_TRACE_ARG_DEBUG : HPFS_TRACE_ARG_ERROR);

            // Fill process args.
            char *execv_args[] = {
                conf::ctx.hpfs_exe_path.data(),
                (char *)"merge",
                conf::ctx.state_dir.data(),
                (char *)active_hpfs_trace_arg,
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            std::cerr << errno << ": hpfs merge process execv failed.\n";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting hpfs merge process.";
            return -1;
        }

        return 0;
    }

    /**
     * Starts hpfs readonly/readwrite process and also starts a virtual fs session.
     */
    int start_ro_rw_process(pid_t &hpfs_pid, std::string &mount_dir, const bool readonly,
                            const bool hash_map_enabled, const bool auto_start_session, const uint16_t timeout)
    {
        const pid_t pid = fork();
        const char *mode = readonly ? "ro" : "rw";

        if (pid > 0)
        {
            // HotPocket process.
            LOG_DEBUG << "Starting hpfs " << mode << " process at " << mount_dir;

            // If the mount dir is not specified, assign a mount dir based on hpfs process id.
            if (mount_dir.empty())
                mount_dir = std::string(conf::ctx.state_dir)
                                .append("/")
                                .append(std::to_string(pid));

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
                    LOG_ERROR << "hpfs process " << pid << " has stopped at " << mount_dir;
                    break;
                }

                // We check for the specific inode no. of the mounted root dir. That means hpfs FUSE interface is up.
                struct stat st;
                if (stat(mount_dir.c_str(), &st) == -1)
                {
                    LOG_ERROR << errno << ": Error in checking hpfs status at " << mount_dir;
                    break;
                }

                hpfs_initialized = (st.st_ino == HPFS_ROOT_INO);
                // Keep retrying until root inode no. matches or timeout occurs.

            } while (!hpfs_initialized && ++retry_count <= max_retries);

            // If hpfs FUSE interface initialized within the timeout period, we then attempt to start up a virtual fs session.
            // hpfs achieves this by having a 'session' file created.
            if (hpfs_initialized && auto_start_session)
                start_fs_session(mount_dir);

            // Kill the process if hpfs couldn't be initialized properly.
            if (!hpfs_initialized)
            {
                LOG_ERROR << "Couldn't initialize hpfs session at " << mount_dir;
                util::kill_process(pid, true);
                return -1;
            }

            hpfs_pid = pid;
            LOG_DEBUG << "hpfs " << mode << " process started at " << mount_dir << " pid:" << hpfs_pid;
        }
        else if (pid == 0)
        {
            // hpfs process.
            util::fork_detach();

            // If the mount dir is not specified, assign a mount dir based on hpfs process id.
            const pid_t self_pid = getpid();
            if (mount_dir.empty())
                mount_dir = std::string(conf::ctx.state_dir)
                                .append("/")
                                .append(std::to_string(self_pid));

            const char *active_hpfs_trace_arg = (conf::cfg.log.loglevel_type == conf::LOG_SEVERITY::DEBUG ? HPFS_TRACE_ARG_DEBUG : HPFS_TRACE_ARG_ERROR);

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
            std::cerr << errno << ": hpfs session process execv failed.\n";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting hpfs process.";
            return -1;
        }

        return 0;
    }

    /**
     * Starts a virtual fs session on the hpfs process attached to the specified mount dir.
     */
    int start_fs_session(std::string_view mount_dir)
    {
        LOG_DEBUG << "Starting hpfs fs session at " << mount_dir;

        const std::string session_file = std::string(mount_dir).append("/").append(HPFS_SESSION);
        if (mknod(session_file.c_str(), 0, 0) == -1)
        {
            LOG_ERROR << errno << ": Error starting hpfs fs session at " << mount_dir;
            return -1;
        }
        return 0;
    }

    /**
     * Stops the active virtual fs session on the hpfs process attached to the specified mount dir.
     */
    int stop_fs_session(std::string_view mount_dir)
    {
        LOG_DEBUG << "Stopping hpfs fs session at " << mount_dir;

        const std::string session_file = std::string(mount_dir).append("/").append(HPFS_SESSION);
        if (unlink(session_file.c_str()) == -1)
        {
            LOG_ERROR << errno << ": Error stopping hpfs fs session at " << mount_dir;
            return -1;
        }
        return 0;
    }

    /**
     * Populates the hash of the specified vpath.
     * @return 1 on success. 0 if vpath not found. -1 on error.
     */
    int get_hash(util::h32 &hash, const std::string_view mount_dir, const std::string_view vpath)
    {
        const std::string path = std::string(mount_dir).append(vpath).append(HPFS_HMAP_HASH);
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1 && errno == ENOENT)
        {
            LOG_DEBUG << "Cannot get hash. vpath not found. " << vpath;
            return 0;
        }
        else if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening hash file. " << vpath;
            return -1;
        }

        const int res = read(fd, &hash, sizeof(util::h32));
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash file. " << vpath;
            return -1;
        }
        return 1;
    }

    /**
     * Populates the list of file block hashes for the specified vpath.
     * @return 1 on success. 0 if vpath not found. -1 on error.
     */
    int get_file_block_hashes(std::vector<util::h32> &hashes, const std::string_view mount_dir, const std::string_view vpath)
    {
        const std::string path = std::string(mount_dir).append(vpath).append(HPFS_HMAP_CHILDREN);
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1 && errno == ENOENT)
        {
            LOG_DEBUG << "Cannot get file block hashes. vpath not found. " << vpath;
            return 0;
        }
        else if (fd == -1)
        {
            LOG_DEBUG << errno << ": Error opening hashmap children. " << vpath;
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error reading block hashes length. " << vpath;
            return -1;
        }

        const int children_count = st.st_size / sizeof(util::h32);
        hashes.resize(children_count);

        const int res = read(fd, hashes.data(), st.st_size);
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading block hashes. " << vpath;
            return -1;
        }
        return 1;
    }

    /**
     * Populates the list of dir entry hashes for the specified vpath.
     * @return 1 on success. 0 if vpath not found. -1 on error.
     */
    int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, const std::string_view mount_dir, const std::string_view dir_vpath)
    {
        const std::string path = std::string(mount_dir).append(dir_vpath).append("::hpfs.hmap.children");
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1 && errno == ENOENT)
        {
            LOG_DEBUG << "Cannot get dir children hashes. Dir vpath not found. " << dir_vpath;
            return 0;
        }
        else if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening dir hash children nodes. " << dir_vpath;
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error reading hash children nodes length. " << dir_vpath;
            return -1;
        }

        const int children_count = st.st_size / sizeof(child_hash_node);
        hash_nodes.resize(children_count);

        const int res = read(fd, hash_nodes.data(), st.st_size);
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash children nodes. " << dir_vpath;
            return -1;
        }
        return 1;
    }

} // namespace hpfs