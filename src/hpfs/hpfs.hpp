#ifndef _HP_HPFS_HPFS_
#define _HP_HPFS_HPFS_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"

namespace hpfs
{
    constexpr size_t BLOCK_SIZE = 4 * 1024 * 1024; // 4MB;

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

    enum HPFS_PARENT_COMPONENTS
    {
        STATE,
        PATCH
    };

    struct hpfs_context
    {
    private:
        std::vector<util::h32> parent_hashes;                                             // Keep hashes of each hpfs parent.
        std::shared_mutex parent_mutexes[2] = {std::shared_mutex(), std::shared_mutex()}; // Mutexes for each parent.

    public:
        pid_t hpfs_merge_pid = 0;
        pid_t hpfs_rw_pid = 0;

        hpfs_context()
        {
            parent_hashes.reserve(2);
            for (size_t i = 0; i < 2; i++)
            {
                parent_hashes.push_back(util::h32_empty);
            }
        }

        util::h32 get_hash(const HPFS_PARENT_COMPONENTS parent)
        {
            std::shared_lock lock(parent_mutexes[parent]);
            return parent_hashes[parent];
        }

        void set_hash(const HPFS_PARENT_COMPONENTS parent, util::h32 new_state)
        {
            std::unique_lock lock(parent_mutexes[parent]);
            parent_hashes[parent] = new_state;
        }
    };

    extern hpfs_context ctx;

    int init();
    void deinit();

    int start_merge_process(pid_t &hpfs_pid);
    int start_ro_rw_process(pid_t &hpfs_pid, std::string &mount_dir, const bool readonly,
                            const bool hash_map_enabled, const bool auto_start_session, const uint16_t timeout = 4000);
    int start_fs_session(std::string_view mount_dir);
    int stop_fs_session(std::string_view mount_dir);
    int get_hash(util::h32 &hash, const std::string_view mount_dir, const std::string_view vpath);
    int get_file_block_hashes(std::vector<util::h32> &hashes, const std::string_view mount_dir, const std::string_view vpath);
    int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, const std::string_view mount_dir, const std::string_view dir_vpath);
} // namespace hpfs

#endif