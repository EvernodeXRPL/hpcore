#ifndef _HP_HPFS_HPFS_MANAGER_
#define _HP_HPFS_HPFS_MANAGER_

#include "./hpfs_mount.hpp"

namespace hpfs_manager
{

    extern hpfs::hpfs_mount contract_fs;
    int init();
    void deinit();

} // namespace hpfs_manager
#endif