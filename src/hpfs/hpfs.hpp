#ifndef _HP_HPFS_HPFS_
#define _HP_HPFS_HPFS_

#include "../pchheader.hpp"
#include "h32.hpp"

namespace hpfs
{
    struct child_hash_node
    {
        bool is_file;
        char name[256];
        h32 hash;
    };

    int init();
    void deinit();
    int start_merge_process();
    int start_fs_session(pid_t &session_pid, std::string &mount_dir,
                         const char *mode, const bool hash_map_enabled);
    int get_root_hash(h32 &hash);
    int get_hash(h32 &hash, const std::string_view mount_dir, const std::string_view vpath);
    int get_file_block_hashes(std::vector<h32> &hashes, const std::string_view mount_dir, const std::string_view vpath);
    int get_dir_children_hashes(std::vector<child_hash_node> &hash_nodes, const std::string_view mount_dir, const std::string_view dir_vpath);
} // namespace hpfs

#endif