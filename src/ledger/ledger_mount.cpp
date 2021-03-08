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
        p2p::sequence_hash last_primary_shard_id;
        p2p::sequence_hash last_blob_shard_id;

        if (acquire_rw_session())
        {
            LOG_ERROR << "Failed to acquire rw session at mount " << mount_dir << ".";
            return -1;
        }

        if (get_last_shard_info(hpfs::RW_SESSION_NAME, last_primary_shard_id, PRIMARY_DIR) == -1 ||
            get_last_ledger_and_update_context(hpfs::RW_SESSION_NAME, last_primary_shard_id) == -1 ||
            get_last_shard_info(hpfs::RW_SESSION_NAME, last_blob_shard_id, BLOB_DIR) == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
            return -1;
        }

        if (conf::cfg.node.history == conf::HISTORY::CUSTOM)
        {
            //Remove old primary shards that exceeds max shard range.
            if (last_primary_shard_id.seq_no >= conf::cfg.node.history_config.max_primary_shards)
                remove_old_shards(last_primary_shard_id.seq_no - conf::cfg.node.history_config.max_primary_shards + 1, PRIMARY_DIR);

            //Remove old blob shards that exceeds max shard range.
            if (last_blob_shard_id.seq_no >= conf::cfg.node.history_config.max_blob_shards)
                remove_old_shards(last_blob_shard_id.seq_no - conf::cfg.node.history_config.max_blob_shards + 1, BLOB_DIR);
        }

        if (release_rw_session())
        {
            LOG_ERROR << "Failed to release rw session at mount " << mount_dir << ".";
            return -1;
        }

        LOG_INFO << "Initial primary: " << last_primary_shard_id << " | blob: " << last_blob_shard_id;

        // Update last shard hash and shard number tracker.
        ctx.set_last_primary_shard_id(last_primary_shard_id);
        // Update last blob shard hash and blob shard number tracker.
        ctx.set_last_blob_shard_id(last_blob_shard_id);
        return 0;
    }

} // namespace ledger