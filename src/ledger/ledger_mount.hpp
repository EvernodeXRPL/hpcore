#ifndef _HP_LEDGER_LEDGER_MOUNT_
#define _HP_LEDGER_LEDGER_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_mount.hpp"

namespace ledger
{
    /**
     * Represents ledger file system mount.
    */
    class ledger_mount : public hpfs::hpfs_mount
    {
    private:
        int prepare_fs();
    };
} // namespace ledger
#endif