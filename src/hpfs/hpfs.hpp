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

    struct hpfs_context
    {
    private:
        util::h32 state;
        std::shared_mutex state_mutex;

    public:
        pid_t hpfs_merge_pid = 0;
        pid_t hpfs_rw_pid = 0;
        util::h32 get_state()
        {
            std::shared_lock lock(state_mutex);
            return state;
        }

        void set_state(util::h32 new_state)
        {
            std::unique_lock lock(state_mutex);
            state = new_state;
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