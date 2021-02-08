#include "./ledger_mount.hpp"

namespace ledger
{
    /**
     * Perform ledger file system mount related preparation tasks.
     * @return Returns -1 on error and 0 on success.
    */
    int ledger_mount::prepare_fs()
    {
        // Add ledger fs preparation logic here.
        util::h32 initial_ledger_primary_hash_hash;

        if (acquire_rw_session() == -1 ||
            get_hash(initial_ledger_primary_hash_hash, hpfs::RW_SESSION_NAME, hpfs::LEDGER_PRIMARY_SHARD_INDEX_PATH) == -1 ||
            release_rw_session() == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
            return -1;
        }

        set_parent_hash(hpfs::LEDGER_PRIMARY_SHARD_INDEX_PATH, initial_ledger_primary_hash_hash);
        LOG_INFO << "Initial ledger_primary_hash: " << initial_ledger_primary_hash_hash;
        return 0;
    }

} // namespace ledger