#ifndef _HP_SC_CONTRACT_MOUNT_
#define _HP_SC_CONTRACT_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_mount.hpp"

namespace sc
{
    constexpr const char *STATE_DIR_PATH = "/state";                              // State directory name.
    constexpr const char *PATCH_FILE_PATH = "/patch.cfg";                         // Config patch filename.
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