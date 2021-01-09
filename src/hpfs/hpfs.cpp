#include "hpfs.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../util/h32.hpp"
#include "../sc.hpp"

namespace hpfs
{
    constexpr const char *TRACE_ARG_ERROR = "trace=error";
    constexpr const char *TRACE_ARG_DEBUG = "trace=error";
    constexpr const char *RW_SESSION = "/::hpfs.rw.hmap";
    constexpr const char *RO_SESSION = "/::hpfs.ro.";
    constexpr const char *RO_SESSION_HMAP = "/::hpfs.ro.hmap.";
    constexpr const char *HMAP_HASH = "::hpfs.hmap.hash";
    constexpr const char *HMAP_CHILDREN = "::hpfs.hmap.children";
    constexpr ino_t ROOT_INO = 1;

    constexpr uint16_t PROCESS_INIT_TIMEOUT = 2000;
    constexpr uint16_t INIT_CHECK_INTERVAL = 20;
    bool init_success = false;
    hpfs_context ctx;

    /**
     * Performs system startup activitites related to hpfs execution.
     */
    int init()
    {
        if (start_hpfs_process(ctx.hpfs_pid) == -1)
            return -1;

        if (prepare_fs() == -1)
        {
            util::kill_process(ctx.hpfs_pid, true);
            return -1;
        }

        init_success = true;
        return 0;
    }

    /**
     * Performs global cleanup related to hpfs execution.
     */
    void deinit()
    {
        if (init_success)
        {
            LOG_DEBUG << "Stopping hpfs process... pid:" << ctx.hpfs_pid;
            if (ctx.hpfs_pid > 0 && util::kill_process(ctx.hpfs_pid, true) == 0)
                LOG_INFO << "Stopped hpfs process.";
        }
    }

    /**
     * Performs initial patch file population and loads initial hashes for later use.
     * @return 0 on success. -1 on failure.
     */
    int prepare_fs()
    {
        util::h32 initial_state_hash;
        util::h32 initial_patch_hash;

        if (acquire_rw_session() == -1 ||
            conf::populate_patch_config() == -1 ||
            get_hash(initial_state_hash, RW_SESSION_NAME, hpfs::STATE_DIR_PATH) == -1 ||
            get_hash(initial_patch_hash, RW_SESSION_NAME, hpfs::PATCH_FILE_PATH) == -1 ||
            release_rw_session() == -1)
        {
            LOG_ERROR << "Failed to get prepare initial fs.";
            return -1;
        }

        ctx.set_hash(HPFS_PARENT_COMPONENTS::STATE, initial_state_hash);
        ctx.set_hash(HPFS_PARENT_COMPONENTS::PATCH, initial_patch_hash);
        LOG_INFO << "Initial state: " << initial_state_hash << " | patch: " << initial_patch_hash;
        return 0;
    }

    /**
     * Starts the hpfs process used for all fs sessions.
     */
    int start_hpfs_process(pid_t &hpfs_pid)
    {
        const pid_t pid = fork();
        if (pid > 0)
        {
            // HotPocket process.

            LOG_DEBUG << "Starting hpfs process.";

            // Wait until hpfs is initialized properly.
            const uint16_t max_retries = PROCESS_INIT_TIMEOUT / INIT_CHECK_INTERVAL;
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

                // We check for the specific inode no. of the mounted root dir. That means hpfs FUSE interface is up.
                struct stat st;
                if (stat(conf::ctx.hpfs_mount_dir.c_str(), &st) == -1)
                {
                    LOG_ERROR << errno << ": Error in checking hpfs status.";
                    break;
                }

                hpfs_initialized = (st.st_ino == ROOT_INO);
                // Keep retrying until root inode no. matches or timeout occurs.

            } while (!hpfs_initialized && ++retry_count <= max_retries);

            // Kill the process if hpfs couldn't be initialized properly.
            if (!hpfs_initialized)
            {
                LOG_ERROR << "Couldn't initialize hpfs process.";
                util::kill_process(pid, true);
                return -1;
            }

            hpfs_pid = pid;
            LOG_DEBUG << "hpfs process started. pid:" << hpfs_pid;
        }
        else if (pid == 0)
        {
            // hpfs process.
            util::fork_detach();

            const char *active_hpfs_trace_arg = (conf::cfg.log.loglevel_type == conf::LOG_SEVERITY::DEBUG ? TRACE_ARG_DEBUG : TRACE_ARG_ERROR);

            // Fill process args.
            char *execv_args[] = {
                conf::ctx.hpfs_exe_path.data(),
                (char *)"fs",
                conf::ctx.hpfs_dir.data(),
                conf::ctx.hpfs_mount_dir.data(),
                // In full history mode, we disable log merge of hpfs.
                (char *)(conf::cfg.node.full_history ? "merge=false" : "merge=true"),
                (char *)active_hpfs_trace_arg,
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            std::cerr << errno << ": hpfs process execv failed.\n";
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
     * Starts a virtual fs ReadWrite session with hash map enabled.
     * If RW session already started, this will simply acquire a consumer reference.
     * @return 0 on success. -1 on failure.
     */
    int acquire_rw_session()
    {
        std::scoped_lock lock(ctx.rw_mutex);

        LOG_DEBUG << "Starting hpfs rw session at " << conf::ctx.hpfs_rw_dir;

        const std::string session_file = conf::ctx.hpfs_mount_dir + RW_SESSION;

        // The sessions creation either should be succesful or should report as already exists (errno=EEXIST).
        // Otherwise we consider it as failure.
        if (mknod(session_file.c_str(), 0, 0) == -1 && errno != EEXIST)
        {
            LOG_ERROR << errno << ": Error starting hpfs rw session at " << conf::ctx.hpfs_rw_dir;
            return -1;
        }
        ctx.rw_consumers++;
        return 0;
    }

    /**
     * Releases a consumer reference to the RW session. If there are no more references,
     * actually stops the running RW session.
     * @return 0 on success. -1 on failure.
     */
    int release_rw_session()
    {
        std::scoped_lock lock(ctx.rw_mutex);

        if (ctx.rw_consumers > 0)
            ctx.rw_consumers--;

        if (ctx.rw_consumers == 0)
        {
            const std::string session_file = conf::ctx.hpfs_mount_dir + RW_SESSION;
            if (unlink(session_file.c_str()) == -1)
            {
                LOG_ERROR << errno << ": Error stopping hpfs rw session at " << conf::ctx.hpfs_rw_dir;
                return -1;
            }
        }
        return 0;
    }

    /**
     * Starts a virtual fs ReadOnly session.
     * @return 0 on success. -1 on failure.
     */
    int start_ro_session(const std::string &name, const bool hmap_enabled)
    {
        LOG_DEBUG << "Starting hpfs ro session " << name << " hmap:" << hmap_enabled;

        const std::string session_file = conf::ctx.hpfs_mount_dir + (hmap_enabled ? RO_SESSION_HMAP : RO_SESSION) + name;
        if (mknod(session_file.c_str(), 0, 0) == -1)
        {
            LOG_ERROR << errno << ": Error starting hpfs ro session " << name;
            return -1;
        }
        return 0;
    }

    /**
     * Stops the specified ReadOnly fs session.
     * @return 0 on success. -1 on failure.
     */
    int stop_ro_session(const std::string &name)
    {
        LOG_DEBUG << "Stopping hpfs ro session " << name;

        const std::string session_file = conf::ctx.hpfs_mount_dir + RO_SESSION + name;
        if (unlink(session_file.c_str()) == -1)
        {
            LOG_ERROR << errno << ": Error stopping hpfs ro session " << name;
            return -1;
        }
        return 0;
    }

    /**
     * Populates the hash of the specified vpath.
     * @return 1 on success. 0 if vpath not found. -1 on error.
     */
    int get_hash(util::h32 &hash, std::string_view session_name, std::string_view vpath)
    {
        const std::string path = physical_path(session_name, std::string(vpath).append(HMAP_HASH));
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
    int get_file_block_hashes(std::vector<util::h32> &hashes, std::string_view session_name, std::string_view vpath)
    {
        const std::string path = physical_path(session_name, std::string(vpath).append(HMAP_CHILDREN));
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
    int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, std::string_view session_name, std::string_view dir_vpath)
    {
        const std::string path = physical_path(session_name, std::string(dir_vpath).append(HMAP_CHILDREN));
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

    const std::string physical_path(std::string_view session_name, std::string_view vpath)
    {
        return conf::ctx.hpfs_mount_dir + "/" + session_name.data() + vpath.data();
    }

} // namespace hpfs