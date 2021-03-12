
#include "./ledger_sync.hpp"
#include "ledger.hpp"

namespace ledger
{
    constexpr const char *HPFS_SESSION_NAME = "ro_shard_sync_status";

    void ledger_sync::on_current_sync_state_acheived(const hpfs::sync_target &synced_target)
    {
        const std::string shard_hash_file_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, synced_target.vpath) + PREV_SHARD_HASH_FILENAME;
        const int fd = open(shard_hash_file_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1)
        {
            LOG_DEBUG << "Cannot read " << shard_hash_file_path;
            return;
        }

        util::h32 prev_shard_hash_from_file;
        // Start reading hash excluding hp_version header.
        const int res = pread(fd, &prev_shard_hash_from_file, sizeof(util::h32), util::HP_VERSION_HEADER_SIZE);
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash file. " << shard_hash_file_path;
            return;
        }
        const size_t pos = synced_target.vpath.find_last_of("/");
        if (pos == std::string::npos)
        {
            LOG_ERROR << "Error retreiving shard no from " << synced_target.vpath;
            return;
        }
        const std::string synced_shard_seq_no_str = synced_target.vpath.substr(pos + 1);
        uint64_t synced_shard_seq_no;
        if (util::stoull(synced_shard_seq_no_str, synced_shard_seq_no) == -1)
        {
            LOG_ERROR << "Error converting shard no from string. " << synced_shard_seq_no_str;
            return;
        }

        util::h32 prev_shard_hash_from_hpfs;
        const std::string shard_parent_dir = synced_target.vpath.substr(0, pos);

        if (shard_parent_dir == PRIMARY_DIR)
        {
            // If the synced shard sequence number is equal or greater than the current shard seq number,
            // then the context information should be updated.
            uint64_t last_primary_shard_seq_no = ctx.get_last_primary_shard_id().seq_no;
            if (last_primary_shard_seq_no <= synced_shard_seq_no)
            {
                // Persist the lastest synced shard seq number to the max shard meta file.
                if (persist_max_shard_seq_no(PRIMARY_DIR, synced_shard_seq_no) == -1)
                {
                    LOG_ERROR << "Error updating max shard meta file in primary shard sync.";
                    return;
                }

                // If existing max shard is older than the max we can keep. Then delete all the existing shards.
                if (conf::cfg.node.history == conf::HISTORY::CUSTOM && synced_shard_seq_no - last_primary_shard_seq_no >= conf::cfg.node.history_config.max_primary_shards)
                    remove_old_shards(last_primary_shard_seq_no + 1, PRIMARY_DIR);

                const p2p::sequence_hash updated_primary_shard_id{synced_shard_seq_no, synced_target.hash};
                if (get_last_ledger_and_update_context(hpfs::RW_SESSION_NAME, updated_primary_shard_id) == -1)
                {
                    LOG_ERROR << "Error updating context from the synced shard " << synced_target.name;
                    return;
                }
                ctx.set_last_primary_shard_id(updated_primary_shard_id);
                last_primary_shard_seq_no = synced_shard_seq_no;
                is_last_primary_shard_syncing = false;
            }

            if (conf::cfg.node.history == conf::HISTORY::FULL || // Sync all shards if this is a full history node.
                last_primary_shard_seq_no - synced_shard_seq_no + 1 < conf::cfg.node.history_config.max_primary_shards)
            {
                // Check whether the hash of the previous shard matches with the hash in the prev_shard.hash file.
                const std::string prev_shard_vpath = std::string(PRIMARY_DIR).append("/").append(std::to_string(--synced_shard_seq_no));
                fs_mount->get_hash(prev_shard_hash_from_hpfs, hpfs::RW_SESSION_NAME, prev_shard_vpath);

                if (prev_shard_hash_from_file != util::h32_empty               // Hash in the prev_shard.hash of the 0th shard is h32 empty. Syncing should be stopped then.
                    && prev_shard_hash_from_file != prev_shard_hash_from_hpfs) // Continue to sync backwards if the hash from prev_shard.hash is not matching with the shard hash from hpfs.
                {
                    const std::string sync_name = "primary shard " + std::to_string(synced_shard_seq_no);
                    const std::string shard_path = std::string(PRIMARY_DIR).append("/").append(std::to_string(synced_shard_seq_no));
                    set_target_push_back(hpfs::sync_target{sync_name, prev_shard_hash_from_file, shard_path, hpfs::BACKLOG_ITEM_TYPE::DIR});
                }
                else if (conf::cfg.node.history == conf::HISTORY::CUSTOM && last_primary_shard_seq_no >= conf::cfg.node.history_config.max_primary_shards)
                {
                    // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                    remove_old_shards(last_primary_shard_seq_no - conf::cfg.node.history_config.max_primary_shards + 1, PRIMARY_DIR);
                }
            }
            else if (conf::cfg.node.history == conf::HISTORY::CUSTOM && last_primary_shard_seq_no >= conf::cfg.node.history_config.max_primary_shards)
            {
                // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                remove_old_shards(last_primary_shard_seq_no - conf::cfg.node.history_config.max_primary_shards + 1, PRIMARY_DIR);
            }
        }
        else if (shard_parent_dir == BLOB_DIR)
        {
            // If the synced blob shard sequence number is equal or greater than the current blob shard seq number,
            // then the context information should be updated.
            uint64_t last_blob_shard_seq_no = ctx.get_last_blob_shard_id().seq_no;
            if (last_blob_shard_seq_no <= synced_shard_seq_no)
            {
                // Persist the lastest synced shard seq number to the max shard meta file.
                if (persist_max_shard_seq_no(BLOB_DIR, synced_shard_seq_no) == -1)
                {
                    LOG_ERROR << "Error updating max shard meta file in blob shard sync.";
                    return;
                }

                // If existing max shard is older than the max we can keep. Then delete all the existing shards.
                if (conf::cfg.node.history == conf::HISTORY::CUSTOM && synced_shard_seq_no - last_blob_shard_seq_no >= conf::cfg.node.history_config.max_blob_shards)
                    remove_old_shards(last_blob_shard_seq_no + 1, BLOB_DIR);

                last_blob_shard_seq_no = synced_shard_seq_no;
                ctx.set_last_blob_shard_id(p2p::sequence_hash{synced_shard_seq_no, synced_target.hash});
                is_last_blob_shard_syncing = false;
            }

            if (conf::cfg.node.history == conf::HISTORY::FULL || // Sync all blob shards if this is a full history node.
                last_blob_shard_seq_no - synced_shard_seq_no + 1 < conf::cfg.node.history_config.max_blob_shards)
            {
                // Check whether the blob hash of the previous blob shard matches with the hash in the prev_shard.hash file.
                const std::string prev_shard_vpath = std::string(BLOB_DIR).append("/").append(std::to_string(--synced_shard_seq_no));
                fs_mount->get_hash(prev_shard_hash_from_hpfs, hpfs::RW_SESSION_NAME, prev_shard_vpath);

                if (prev_shard_hash_from_file != util::h32_empty               // Hash in the prev_shard.hash of the 0th shard is h32 empty. Syncing should be stopped then.
                    && prev_shard_hash_from_file != prev_shard_hash_from_hpfs) // Continue to sync backwards if the hash from prev_shard.hash is not matching with the shard hash from hpfs.
                {
                    const std::string sync_name = "blob shard " + std::to_string(synced_shard_seq_no);
                    const std::string shard_path = std::string(BLOB_DIR).append("/").append(std::to_string(synced_shard_seq_no));
                    set_target_push_back(hpfs::sync_target{sync_name, prev_shard_hash_from_file, shard_path, hpfs::BACKLOG_ITEM_TYPE::DIR});
                }
                else if (conf::cfg.node.history == conf::HISTORY::CUSTOM && last_blob_shard_seq_no >= conf::cfg.node.history_config.max_blob_shards)
                {
                    // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                    remove_old_shards(last_blob_shard_seq_no - conf::cfg.node.history_config.max_blob_shards + 1, BLOB_DIR);
                }
            }
            else if (conf::cfg.node.history == conf::HISTORY::CUSTOM && last_blob_shard_seq_no >= conf::cfg.node.history_config.max_blob_shards)
            {
                // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                remove_old_shards(last_blob_shard_seq_no - conf::cfg.node.history_config.max_blob_shards + 1, BLOB_DIR);
            }
        }
    }

    void ledger_sync::swap_collected_responses()
    {
        std::scoped_lock lock(p2p::ctx.collected_msgs.ledger_hpfs_responses_mutex);

        // Move collected hpfs responses over to local candidate responses list.
        if (!p2p::ctx.collected_msgs.ledger_hpfs_responses.empty())
            candidate_hpfs_responses.splice(candidate_hpfs_responses.end(), p2p::ctx.collected_msgs.ledger_hpfs_responses);
    }

} // namespace ledger