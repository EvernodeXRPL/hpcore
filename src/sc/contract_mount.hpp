#ifndef _HP_SC_CONTRACT_MOUNT_
#define _HP_SC_CONTRACT_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_mount.hpp"

namespace sc
{
    /**
     * Represents contract file system mount.
    */
    class contract_mount : public hpfs::hpfs_mount
    {
    private:
        int prepare_fs();
    };
} // namespace sc
#endif