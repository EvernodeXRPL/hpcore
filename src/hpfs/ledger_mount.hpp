#ifndef _HP_HPFS_LEDGER_MOUNT_
#define _HP_HPFS_LEDGER_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "./hpfs_mount.hpp"

namespace hpfs
{
    /**
     * Represents ledger file system mount.
    */
    class ledger_mount: public hpfs_mount
    {
        private:
            int prepare_fs();
    };
} // namespace hpfs
#endif