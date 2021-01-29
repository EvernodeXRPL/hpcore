#ifndef _HP_HPFS_HPFS_MOUNT_
#define _HP_HPFS_HPFS_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"

namespace hpfs
{
    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024;        // 4MB;
    constexpr const char *RW_SESSION_NAME = "rw";         // The built-in session name used by hpfs for RW sessions.
    constexpr const char *STATE_DIR_PATH = "/state";      // State directory name.
    constexpr const char *PATCH_FILE_PATH = "/patch.cfg"; // Config patch filename.

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

    inline uint16_t get_request_resubmit_timeout()
    {
        return conf::cfg.contract.roundtime;
    }

    enum MOUNTS
    {
        CONTRACT
    };

    struct hpfs_context
    {
    private:
        std::unordered_map<std::string, util::h32> parent_hashes; // Keep hashes of each hpfs parent.
        std::shared_mutex parent_hashes_mutex;

    public:
        pid_t hpfs_pid = 0;

        // No. of consumers for RW session.
        // We use this as a reference counting mechanism to cleanup RW session when no one requires it.
        uint32_t rw_consumers = 0;
        std::mutex rw_mutex;

        util::h32 get_hash(const std::string &parent_vpath)
        {
            std::shared_lock lock(parent_hashes_mutex);
            const auto itr = parent_hashes.find(parent_vpath);
            if (itr == parent_hashes.end())
            {
                return util::h32_empty; // Looking parent_vpath is not found.
            }
            return itr->second;
        }

        void set_hash(const std::string &parent_vpath, util::h32 new_state)
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
    };

    class hpfs_mount
    {
    private:
        std::string fs_dir;
        std::string mount_dir;
        bool is_full_history;
        bool init_success = false;

    public:
        std::string rw_dir;
        MOUNTS mount_type;
        hpfs_context ctx;
        int init(MOUNTS mount_type, std::string_view fs_dir, std::string_view mount_dir, std::string_view rw_dir, bool is_full_history);
        void deinit();
        int prepare_fs();

        int start_hpfs_process();
        int acquire_rw_session();
        int release_rw_session();
        int start_ro_session(const std::string &name, const bool hmap_enabled);
        int stop_ro_session(const std::string &name);
        int get_hash(util::h32 &hash, std::string_view session_name, std::string_view vpath);
        int get_file_block_hashes(std::vector<util::h32> &hashes, std::string_view session_name, std::string_view vpath);
        int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, std::string_view session_name, std::string_view dir_vpath);
        const std::string physical_path(std::string_view session_name, std::string_view vpath);
    };

} // namespace hpfs

#endif