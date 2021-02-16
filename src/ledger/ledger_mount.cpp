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
        util::h32 initial_last_primary_ledger_hash;
        uint64_t initial_primary_shard_seq_no = 0;
        util::h32 initial_last_blob_ledger_hash;
        uint64_t initial_blob_shard_seq_no = 0;
        constexpr const char * session_name = "ro_ledger_prepare_fs";

        if (start_ro_session(session_name, true) == -1 ||
            get_last_shard_info(session_name, initial_last_primary_ledger_hash, initial_primary_shard_seq_no, PRIMARY_DIR) == -1 ||
            get_last_shard_info(session_name, initial_last_blob_ledger_hash, initial_blob_shard_seq_no, BLOB_DIR) == -1 ||
            stop_ro_session(session_name) == -1)
        {
            LOG_ERROR << "Failed to prepare initial fs at mount " << mount_dir << ".";
            return -1;
        }

        LOG_INFO << "Initial last shard hash: " << initial_last_primary_ledger_hash;
        // Update last shard hash and shard number tracker.
        ctx.set_last_primary_shard_hash(initial_primary_shard_seq_no, initial_last_primary_ledger_hash);

        LOG_INFO << "Initial last blob shard hash: " << initial_last_blob_ledger_hash;
        // Update last blob shard hash and blob shard number tracker.
        ctx.set_last_blob_shard_hash(initial_blob_shard_seq_no, initial_last_blob_ledger_hash);
        return 0;
    }

} // namespace ledger