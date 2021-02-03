#ifndef _HP_HPFS_HPFS
#define _HP_HPFS_HPFS

#include "./hpfs_mount.hpp"
#include "./hpfs_sync.hpp"

namespace hpfs
{
    constexpr int32_t CONTRACT_FS_ID = 0;

    // "/ledger_temp/primary" should be made as a constant when ledger fs is implemented.
    constexpr const char *PRIMARY_DIR_PATH = "/ledger_temp/primary";

    extern hpfs::hpfs_mount contract_fs;  // Global contract file system instance.
    extern hpfs::hpfs_sync contract_sync; // Global contract file system sync instance.
    int init();
    void deinit();

} // namespace hpfs
#endif