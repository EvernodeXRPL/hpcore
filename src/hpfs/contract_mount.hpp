#ifndef _HP_HPFS_CONTRACT_MOUNT_
#define _HP_HPFS_CONTRACT_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "./hpfs_mount.hpp"

namespace hpfs
{
    class contract_mount: public hpfs_mount
    {
        private:
            int prepare_fs();
    };
} // namespace hpfs
#endif