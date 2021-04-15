#ifndef _HP_LEDGER_LEDGER_MOUNT_
#define _HP_LEDGER_LEDGER_MOUNT_

#include "../pchheader.hpp"
#include "../util/h32.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_mount.hpp"

namespace ledger
{
    constexpr const char *PRIMARY_DIR = "/primary";                      // Ledger primary directory name.
    constexpr const char *RAW_DIR = "/raw";                              // Ledger raw data directory name.
    constexpr const char *PREV_SHARD_HASH_FILENAME = "/prev_shard.hash"; // Previous shard hash file name.
    constexpr const char *SHARD_SEQ_NO_FILENAME = "/max_shard.seq_no";   // Meta file containing the maximum shard seq number information.
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