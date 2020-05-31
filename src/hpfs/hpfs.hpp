#ifndef _HP_HPFS_HPFS_
#define _HP_HPFS_HPFS_

#include "../pchheader.hpp"
#include "h32.hpp"

namespace hpfs
{
    int init();
    void deinit();
    int start_merge_process();
    int start_fs_session(pid_t &session_pid, std::string &mount_dir,
                         const char *mode, const bool hash_map_enabled);
    int get_root_hash(h32 &hash);
    int get_hash(h32 &hash, const std::string_view mount_dir, const std::string_view vpath);
} // namespace hpfs

#endif