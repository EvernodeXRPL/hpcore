#ifndef _HP_HPFS_HPFS_
#define _HP_HPFS_HPFS_

#include "../pchheader.hpp"
#include "../util/h32.hpp"

namespace hpfs
{
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

    // File block size;
    constexpr size_t BLOCK_SIZE = 4194304; // 4MB

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