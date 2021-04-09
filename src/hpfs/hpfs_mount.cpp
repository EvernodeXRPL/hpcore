#include "hpfs_mount.hpp"
#include "../conf.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../util/h32.hpp"
#include "../sc/sc.hpp"
#include "../crypto.hpp"
#include "../util/version.hpp"

namespace hpfs
{
    constexpr const char *TRACE_ARG_ERROR = "trace=error";
    // Trace is set to error intentionally to prevent log pollution in debug mode. Change this in hpfs specific debugging.
    constexpr const char *TRACE_ARG_DEBUG = "trace=error";
    constexpr const char *RW_SESSION = "/::hpfs.rw.hmap";
    constexpr const char *RO_SESSION = "/::hpfs.ro.";
    constexpr const char *RO_SESSION_HMAP = "/::hpfs.ro.hmap.";
    constexpr const char *HMAP_HASH = "::hpfs.hmap.hash";
    constexpr const char *HMAP_CHILDREN = "::hpfs.hmap.children";

    constexpr const char *INDEX_CONTROL = "/::hpfs.index";
    constexpr const char *INDEX_READ_QUERY_FULLSTOP = "/::hpfs.index.read.";
    constexpr const char *INDEX_WRITE_QUERY_FULLSTOP = "/::hpfs.index.write.";
    constexpr const char *ROOT_PATH = "/";
    constexpr const char *LOG_INDEX_FILENAME = "/log.hpfs.idx";

    constexpr ino_t ROOT_INO = 1;

    constexpr uint16_t PROCESS_INIT_TIMEOUT = 2000;
    constexpr uint16_t INIT_CHECK_INTERVAL = 20;

    constexpr uint64_t MAX_HPFS_LOG_READ_SIZE = 4 * 1024 * 1024;

    /**
     * This should be called to activate the hpfs mount process.
     */
    int hpfs_mount::init(const uint32_t mount_id, std::string_view fs_dir, std::string_view mount_dir, std::string_view rw_dir, const bool is_full_history)
    {
        this->mount_id = mount_id;
        this->fs_dir = fs_dir;
        this->mount_dir = mount_dir;
        this->rw_dir = rw_dir;
        this->is_full_history = is_full_history;
        if (start_hpfs_process() == -1)
            return -1;

        if (prepare_fs() == -1)
        {
            stop_hpfs_process();
            return -1;
        }

        init_success = true;
        return 0;
    }

    /**
     * Performs cleanup related to hpfs mount execution.
     */
    void hpfs_mount::deinit()
    {
        if (init_success)
        {
            stop_hpfs_process();
        }
    }

    /**
     * This perform file system preparation tasks.
     * @return 0 on success. -1 on failure.
     */
    int hpfs_mount::prepare_fs()
    {
        return 0;
    }

    /**
     * Starts the hpfs process used for all fs sessions of the mount.
     */
    int hpfs_mount::start_hpfs_process()
    {
        if (conf::cfg.hpfs.external)
            return 0;

        const pid_t pid = fork();
        if (pid > 0)
        {
            // HotPocket process.

            LOG_DEBUG << "Starting hpfs process at " << mount_dir << ".";

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
                if (stat(mount_dir.data(), &st) == -1)
                {
                    LOG_ERROR << errno << ": Error in checking hpfs status at mount " << mount_dir << ".";
                    break;
                }

                hpfs_initialized = (st.st_ino == ROOT_INO);
                // Keep retrying until root inode no. matches or timeout occurs.

            } while (!hpfs_initialized && ++retry_count <= max_retries);

            // Kill the process if hpfs couldn't be initialized properly.
            if (!hpfs_initialized)
            {
                LOG_ERROR << "Couldn't initialize hpfs process at mount " << mount_dir << ".";
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
                (char *)fs_dir.data(),
                (char *)mount_dir.data(),
                // In full history mode, we disable log merge of hpfs.
                (char *)(is_full_history ? "merge=false" : "merge=true"),
                (char *)active_hpfs_trace_arg,
                NULL};

            const int ret = execv(execv_args[0], execv_args);
            std::cerr << errno << ": hpfs process execv failed at mount " << mount_dir << ".\n";
            exit(1);
        }
        else
        {
            LOG_ERROR << errno << ": fork() failed when starting hpfs process at mount " << mount_dir << ".";
            return -1;
        }

        return 0;
    }

    void hpfs_mount::stop_hpfs_process()
    {
        LOG_DEBUG << "Stopping hpfs process... pid:" << hpfs_pid;
        if (!conf::cfg.hpfs.external && hpfs_pid > 0 && util::kill_process(hpfs_pid, true) == 0)
        {
            hpfs_pid = 0;
            LOG_INFO << "Stopped hpfs process.";
        }
    }

    /**
     * Starts a virtual fs ReadWrite session with hash map enabled.
     * If RW session already started, this will simply acquire a consumer reference.
     * @return 0 on success. -1 on failure.
     */
    int hpfs_mount::acquire_rw_session()
    {
        std::scoped_lock lock(rw_mutex);

        LOG_DEBUG << "Starting hpfs rw session at " << rw_dir;

        const std::string session_file = mount_dir + RW_SESSION;

        // The sessions creation either should be succesful or should report as already exists (errno=EEXIST).
        // Otherwise we consider it as failure.
        if (mknod(session_file.c_str(), 0, 0) == -1 && errno != EEXIST)
        {
            LOG_ERROR << errno << ": Error starting hpfs rw session at " << rw_dir;
            return -1;
        }
        rw_consumers++;
        return 0;
    }

    /**
     * Releases a consumer reference to the RW session. If there are no more references,
     * actually stops the running RW session.
     * @return 0 on success. -1 on failure.
     */
    int hpfs_mount::release_rw_session()
    {
        std::scoped_lock lock(rw_mutex);

        if (rw_consumers > 0)
            rw_consumers--;

        if (rw_consumers == 0)
        {
            const std::string session_file = mount_dir + RW_SESSION;
            if (unlink(session_file.c_str()) == -1)
            {
                LOG_ERROR << errno << ": Error stopping hpfs rw session at " << rw_dir;
                return -1;
            }
        }
        return 0;
    }

    /**
     * Starts a virtual fs ReadOnly session.
     * @return 0 on success. -1 on failure.
     */
    int hpfs_mount::start_ro_session(const std::string &name, const bool hmap_enabled)
    {
        LOG_DEBUG << "Starting hpfs ro session " << name << " hmap:" << hmap_enabled;

        const std::string session_file = mount_dir + (hmap_enabled ? RO_SESSION_HMAP : RO_SESSION) + name;
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
    int hpfs_mount::stop_ro_session(const std::string &name)
    {
        LOG_DEBUG << "Stopping hpfs ro session " << name;

        const std::string session_file = mount_dir + RO_SESSION + name;
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
    int hpfs_mount::get_hash(util::h32 &hash, std::string_view session_name, std::string_view vpath)
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
    int hpfs_mount::get_file_block_hashes(std::vector<util::h32> &hashes, std::string_view session_name, std::string_view vpath)
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
    int hpfs_mount::get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, std::string_view session_name, std::string_view dir_vpath)
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

    const std::string hpfs_mount::physical_path(std::string_view session_name, std::string_view vpath)
    {
        return mount_dir + "/" + session_name.data() + vpath.data();
    }

    /**
     * This returns the hash of a given parent.
     * @param parent_vpath vpath of the parent file or directory.
     * @return The hash of the given vpath if available or an empth h32 hash if parent vpath not available.
    */
    const util::h32 hpfs_mount::get_parent_hash(const std::string &parent_vpath)
    {
        std::shared_lock lock(parent_hashes_mutex);
        const auto itr = parent_hashes.find(parent_vpath);
        if (itr == parent_hashes.end())
        {
            return util::h32_empty; // Looking parent_vpath is not found.
        }
        return itr->second;
    }

    /**
     * This set the hash of a given parent.
     * @param parent_vpath vpath of the parent file or directory.
     * @param new_state Hash of the parent.
    */
    void hpfs_mount::set_parent_hash(const std::string &parent_vpath, const util::h32 new_state)
    {
        std::unique_lock lock(parent_hashes_mutex);
        const auto itr = parent_hashes.find(parent_vpath);
        if (itr == parent_hashes.end())
        {
            parent_hashes.try_emplace(parent_vpath, new_state);
        }
        else
        {
            itr->second = new_state;
        }
    }

    /**
     * This updates the hpfs log index file with latest log offset and the root hash.
     * @return Returns 0 in success, otherwise -1.
    */
    int hpfs_mount::update_hpfs_log_index()
    {
        const std::string index_file = mount_dir + INDEX_CONTROL;

        const int fd = open(index_file.c_str(), O_RDWR);
        if (fd == -1)
            return -1;

        // We just send empty buffer with write size 1 to invoke the hpfs index update.
        // Write syscall isn't invoking with write size 0.
        if (write(fd, "", 1) == -1)
        {
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Invoke log file and hpfs index file starting from the given sequence number. This function is a blocking call.
     * @param seq_no Sequence number to start truncation from.
     * @return -1 on error and 0 on success.
    */
    int hpfs_mount::truncate_log_file(const uint64_t seq_no)
    {
        const std::string file_path = mount_dir + INDEX_CONTROL + "." + std::to_string(seq_no);
        // File /hpfs::index.<seq_no> is truncated to invoke log file truncation in hpfs.
        // This call waits until any running RW or RO sessions stop.
        if (truncate(file_path.c_str(), 0) == -1)
        {
            LOG_ERROR << errno << ": Error truncating log file for seq_no: " << std::to_string(seq_no);
            return -1;
        }
        return 0;
    }

    /**
     * This reads the hpfs logs from given min to max ledger seq_no range.
     * Read call will handled as chuncks in multiple threads from the hpfs. 
     * So this function should only be called in a single thread.
     * @param min_ledger_seq_no Mininmum ledger seq number.
     * @param max_ledger_seq_no Maximum ledger seq number.
     * @param buf Buffer to read logs.
     * @return Returns 0 if success, otherwise -1.
    */
    int hpfs_mount::read_hpfs_logs(const uint64_t min_ledger_seq_no, const uint64_t max_ledger_seq_no, std::vector<uint8_t> &buf)
    {
        /**
         * To complete the read operation. All the three open(), read() ad close() operations should be done in this order.
         * This should be done within a single thread in atomic manner.
        */
        const std::string index_file = mount_dir + INDEX_READ_QUERY_FULLSTOP + std::to_string(min_ledger_seq_no) + "." + std::to_string(max_ledger_seq_no);

        const int fd = open(index_file.c_str(), O_RDONLY);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening the hpfs logs file";
            return -1;
        }

        // First resize the buffer to max size and then after reading resize it to the actual read size.
        buf.resize(MAX_HPFS_LOG_READ_SIZE);
        const int res = read(fd, buf.data(), MAX_HPFS_LOG_READ_SIZE);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading the hpfs logs file";
            close(fd);
            return -1;
        }
        buf.resize(res);
        close(fd);
        return 0;
    }

    /**
     * This appends new log records to the hpfs log file.
     * Write call will handled as chuncks in multiple threads from the hpfs. 
     * So this function should only be called in a single thread.
     * @param buf Hpfs log record buffer to write.
     * @return Returns 0 in success, otherwise -1.
    */
    int hpfs_mount::append_hpfs_log_records(const std::vector<uint8_t> &buf)
    {
        /**
         * To complete the read operation. All the three open(), write() ad close() operations should be done in this order.
         * This should be done within a single thread in atomic manner.
        */
        const std::string index_file = mount_dir + INDEX_WRITE_QUERY_FULLSTOP + std::to_string(buf.size());

        const int fd = open(index_file.c_str(), O_RDWR);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening the hpfs logs file";
            return -1;
        }

        if (write(fd, buf.data(), buf.size()) == -1)
        {
            LOG_ERROR << errno << ": Error writing to the hpfs logs file";
            close(fd);
            return -1;
        }

        close(fd);
        return 0;
    }

    /**
     * Get the last sequence number updated in the index file.
     * @param seq_no The last sequence number.
     * @return -1 on error and 0 on success.
    */
    int hpfs_mount::get_last_seq_no_from_index(uint64_t &seq_no)
    {
        const std::string path = fs_dir + "/" + LOG_INDEX_FILENAME;
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);

        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening hpfs index file " << path;
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            close(fd);
            LOG_ERROR << errno << ": Error reading hpfs index file " << path;
            return -1;
        }
        close(fd);
        seq_no = (st.st_size - version::HPFS_VERSION_BYTES_LEN) / (sizeof(uint64_t) + sizeof(util::h32));
        return 0;
    }

    /**
     * Get the root hash for the given sequence number from hpfs index file.
     * @param hash Root hash in the state of given sequence number.
     * @param seq_no Sequence number to get the root hash of.
     * @return -1 on error and 0 on success.
    */
    int hpfs_mount::get_hash_from_index_by_seq_no(util::h32 &hash, const uint64_t seq_no)
    {
        const std::string path = fs_dir + "/" + LOG_INDEX_FILENAME;
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);

        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error opening hpfs index file " << path;
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1)
        {
            LOG_ERROR << errno << ": Error stat hpfs index file " << path;
            return -1;
        }

        const off_t offset = version::HPFS_VERSION_BYTES_LEN + ((seq_no - 1) * (sizeof(uint64_t) + sizeof(util::h32))) + sizeof(uint64_t);
        // If calculated offset is beyond our file size means,
        // Requested seq_no is invalid or we do not have that seq_no in our hpfs log file.
        if (offset >= st.st_size)
        {
            LOG_DEBUG << "Requested hash does not exist in hpfs log file: seq no " << seq_no;
            close(fd);
            return -1;
        }

        if (pread(fd, &hash, sizeof(util::h32), offset) < sizeof(util::h32))
        {
            LOG_ERROR << errno << ": Error reading hash from the given offset " << offset;
            close(fd);
            return -1;
        }
        close(fd);
        return 0;
    }

    /**
     * Returns root hash when the two childrens are given.
     * @param child_one First child of the root.
     * @param child_two Second child of the root.
     * @return The calculated root hash.
    */
    const util::h32 get_root_hash(const util::h32 &child_one, const util::h32 &child_two)
    {
        util::h32 name_hash;
        name_hash = crypto::get_hash(ROOT_PATH);

        util::h32 root_hash = name_hash;
        root_hash ^= child_one;
        root_hash ^= child_two;

        return root_hash;
    }

    /**
     * Returns root hash when the two childrens are given.
     * @param child_one First child of the root.
     * @param child_two Second child of the root.
     * @return The calculated root hash.
    */
    const util::h32 get_root_hash(std::string_view child_one, std::string_view child_two)
    {

        util::h32 h32_child_one;
        util::h32 h32_child_two;

        h32_child_one = child_one;
        h32_child_two = child_two;

        return get_root_hash(h32_child_one, h32_child_two);
    }

} // namespace hpfs