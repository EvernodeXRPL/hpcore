#ifndef _HP_HPFS_HPFS_MANAGER_
#define _HP_HPFS_HPFS_MANAGER_

#include "./hpfs_mount.hpp"
#include "./hpfs_sync.hpp"

namespace hpfs_manager
{
    constexpr int32_t CONTRACT_FS_ID = 0;

    extern hpfs::hpfs_mount contract_fs;  // Global contract file system instance.
    extern hpfs::hpfs_sync contract_sync; // Global contract file system sync instance.
    int init();
    void deinit();

} // namespace hpfs_manager
#endif