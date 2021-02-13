#include "./ledger_mount.hpp"
#include "ledger.hpp"

namespace ledger
{
    /**
     * Perform ledger file system mount related preparation tasks.
     * @return Returns -1 on error and 0 on success.
    */
    int ledger_mount::prepare_fs()
    {
        // Add ledger fs preparation logic here.
        util::h32 initial_last_ledger_hash;
        uint64_t initial_shard_seq_no = 0;

        if (acquire_rw_session() == -1 ||
            get_last_shard_info(hpfs::RW_SESSION_NAME, initial_last_ledger_hash, initial_shard_seq_no) == -1 ||
            release_rw_session() == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
            return -1;
        }

        LOG_INFO << "Initial last shard hash: " << initial_last_ledger_hash;
        // Update last shard hash and shard number tracker.
        ctx.set_last_shard_hash(initial_shard_seq_no, initial_last_ledger_hash);
        return 0;
    }

} // namespace ledger