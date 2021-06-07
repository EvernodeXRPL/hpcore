#include "../util/sequence_hash.hpp"
#include "ledger_mount.hpp"
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
        util::sequence_hash last_primary_shard_id;
        util::sequence_hash last_raw_shard_id;

        if (acquire_rw_session() == -1)
        {
            LOG_ERROR << "Failed to acquire rw session at mount " << mount_dir << ".";
            return -1;
        }

        // For the get last ledger, we pass genesis_fallback=true because in case the ledger db is found to be corrupted during startup,
        // the node can start with genesis ledger and (hopefuly) the ledger syncing will auto correct the currupted ledger db.

        if (get_last_shard_info(hpfs::RW_SESSION_NAME, last_primary_shard_id, PRIMARY_DIR) == -1 ||
            get_last_ledger_and_update_context(hpfs::RW_SESSION_NAME, last_primary_shard_id, true) == -1 ||
            get_last_shard_info(hpfs::RW_SESSION_NAME, last_raw_shard_id, RAW_DIR) == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
            return -1;
        }

        if (release_rw_session() == -1)
        {
            LOG_ERROR << "Failed to release rw session at mount " << mount_dir << ".";
            return -1;
        }

        LOG_INFO << "Ledger primary:" << last_primary_shard_id << " | raw:" << last_raw_shard_id;

        // Update last shard hash and shard number tracker.
        ctx.set_last_primary_shard_id(last_primary_shard_id);
        // Update last raw shard hash and raw shard number tracker.
        ctx.set_last_raw_shard_id(last_raw_shard_id);
        return 0;
    }

} // namespace ledger