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
        constexpr const char *session_name = "ro_ledger_prepare_fs";

        if (start_ro_session(session_name, true) == -1 ||
            get_last_shard_info(session_name, last_primary_shard_id, PRIMARY_DIR) == -1 ||
            get_last_shard_info(session_name, last_blob_shard_id, BLOB_DIR) == -1 ||
            stop_ro_session(session_name) == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
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