#ifndef _HP_HPFS_HPFS_MOUNT_
#define _HP_HPFS_HPFS_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"

namespace hpfs
{
    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024;                                // 4MB;
    constexpr const char *RW_SESSION_NAME = "rw";                                 // The built-in session name used by hpfs for RW sessions.

    struct child_hash_node
    {
        bool is_file = false;
        char name[256];
        util::h32 hash;

        child_hash_node()
        {
            memset(name, 0, sizeof(name));
        }
    };

    inline uint32_t get_request_resubmit_timeout()
    {
        return conf::cfg.contract.roundtime;
    }

    /**
     * This class represents a hpfs file system mount.
     */
    class hpfs_mount
    {
    private:
        pid_t hpfs_pid = 0;
        std::string fs_dir;
        bool is_full_history = false;
        bool init_success = false;
        // Keeps the hashes of hpfs parents against its vpath.
        std::unordered_map<std::string, util::h32> parent_hashes;
        std::shared_mutex parent_hashes_mutex;
        // No. of consumers for RW session.
        // We use this as a reference counting mechanism to cleanup RW session when no one requires it.
        uint32_t rw_consumers = 0;
        std::mutex rw_mutex;
        int start_hpfs_process();
        void stop_hpfs_process();

    protected:
        std::string mount_dir;
        virtual int prepare_fs();

    public:
        uint32_t mount_id; // Used in hpfs serving and syncing.
        std::string rw_dir;
        int init(const uint32_t mount_id, std::string_view fs_dir, std::string_view mount_dir, std::string_view rw_dir, const bool is_full_history);
        void deinit();

        int acquire_rw_session();
        int release_rw_session();
        int start_ro_session(const std::string &name, const bool hmap_enabled);
        int stop_ro_session(const std::string &name);
        int get_hash(util::h32 &hash, std::string_view session_name, std::string_view vpath);
        int get_file_block_hashes(std::vector<util::h32> &hashes, std::string_view session_name, std::string_view vpath);
        int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, std::string_view session_name, std::string_view dir_vpath);
        const std::string physical_path(std::string_view session_name, std::string_view vpath);
        const util::h32 get_parent_hash(const std::string &parent_vpath);
        void set_parent_hash(const std::string &parent_vpath, const util::h32 new_state);
        int update_hpfs_log_index();
    };

} // namespace hpfs

#endif