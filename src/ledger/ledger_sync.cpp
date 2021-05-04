
#include "ledger_sync.hpp"
#include "ledger.hpp"
#include "../util/version.hpp"

namespace ledger
{
    constexpr const char *HPFS_SESSION_NAME = "ro_shard_sync_status";

    void ledger_sync::on_sync_target_acheived(const hpfs::sync_target &synced_target)
    {
        const std::string shard_hash_file_path = fs_mount->physical_path(hpfs::RW_SESSION_NAME, synced_target.vpath) + PREV_SHARD_HASH_FILENAME;
        const int fd = open(shard_hash_file_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1)
        {
            LOG_DEBUG << "Cannot read " << shard_hash_file_path;
            return;
        }

        util::h32 prev_shard_hash_from_file;
        // Start reading hash excluding version bytes.
        const int res = pread(fd, &prev_shard_hash_from_file, sizeof(util::h32), version::VERSION_BYTES_LEN);
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
                    LOG_ERROR << "Error updating max shard meta file in primary shard sync. " << synced_target.vpath;
                    return;
                }

                const p2p::sequence_hash updated_primary_shard_id{synced_shard_seq_no, synced_target.hash};
                if (get_last_ledger_and_update_context(hpfs::RW_SESSION_NAME, updated_primary_shard_id) == -1)
                {
                    LOG_ERROR << "Error updating context from the synced shard " << synced_target.vpath;
                    return;
                }
                ctx.set_last_primary_shard_id(updated_primary_shard_id);
                last_primary_shard_seq_no = synced_shard_seq_no;
                is_last_primary_shard_syncing = false;

                // If existing max shard is older than the max we can keep. Then delete all the existing shards.
                remove_old_shards(ctx.get_lcl_id().seq_no, PRIMARY_SHARD_SIZE, conf::cfg.node.history_config.max_primary_shards, PRIMARY_DIR);
            }

            if (conf::cfg.node.history == conf::HISTORY::FULL || // Sync all shards if this is a full history node.
                last_primary_shard_seq_no - synced_shard_seq_no + 1 < conf::cfg.node.history_config.max_primary_shards)
            {
                // Check whether the hash of the previous shard matches with the hash in the prev_shard.hash file.
                util::h32 prev_shard_hash_from_hpfs = util::h32_empty;
                if (synced_shard_seq_no > 0)
                {
                    const std::string prev_shard_vpath = std::string(PRIMARY_DIR).append("/").append(std::to_string(--synced_shard_seq_no));
                    fs_mount->get_hash(prev_shard_hash_from_hpfs, hpfs::RW_SESSION_NAME, prev_shard_vpath);
                }

                if (prev_shard_hash_from_file != util::h32_empty               // Hash in the prev_shard.hash of the 0th shard is h32 empty. Syncing should be stopped then.
                    && prev_shard_hash_from_file != prev_shard_hash_from_hpfs) // Continue to sync backwards if the hash from prev_shard.hash is not matching with the shard hash from hpfs.
                {
                    const std::string shard_path = std::string(PRIMARY_DIR).append("/").append(std::to_string(synced_shard_seq_no));
                    set_target_push_back(hpfs::sync_target{prev_shard_hash_from_file, shard_path, hpfs::BACKLOG_ITEM_TYPE::DIR});
                }
                else
                {
                    // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                    remove_old_shards(ctx.get_lcl_id().seq_no, PRIMARY_SHARD_SIZE, conf::cfg.node.history_config.max_primary_shards, PRIMARY_DIR);
                }
            }
            else
            {
                // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                remove_old_shards(ctx.get_lcl_id().seq_no, PRIMARY_SHARD_SIZE, conf::cfg.node.history_config.max_primary_shards, PRIMARY_DIR);
            }
        }
        else if (shard_parent_dir == RAW_DIR)
        {
            // If the synced raw shard sequence number is equal or greater than the current raw shard seq number,
            // then the context information should be updated.
            uint64_t last_raw_shard_seq_no = ctx.get_last_raw_shard_id().seq_no;
            if (last_raw_shard_seq_no <= synced_shard_seq_no)
            {
                // Persist the lastest synced shard seq number to the max shard meta file.
                if (persist_max_shard_seq_no(RAW_DIR, synced_shard_seq_no) == -1)
                {
                    LOG_ERROR << "Error updating max shard meta file in raw shard sync.";
                    return;
                }

                last_raw_shard_seq_no = synced_shard_seq_no;
                ctx.set_last_raw_shard_id(p2p::sequence_hash{synced_shard_seq_no, synced_target.hash});
                is_last_raw_shard_syncing = false;

                // If existing max shard is older than the max we can keep. Then delete all the existing shards.
                remove_old_shards(ctx.get_lcl_id().seq_no, RAW_SHARD_SIZE, conf::cfg.node.history_config.max_raw_shards, RAW_DIR);
            }

            if (conf::cfg.node.history == conf::HISTORY::FULL || // Sync all raw shards if this is a full history node.
                last_raw_shard_seq_no - synced_shard_seq_no + 1 < conf::cfg.node.history_config.max_raw_shards)
            {
                // Check whether the hash of the previous raw shard matches with the hash in the prev_shard.hash file.
                util::h32 prev_shard_hash_from_hpfs = util::h32_empty;
                if (synced_shard_seq_no > 0)
                {
                    const std::string prev_shard_vpath = std::string(RAW_DIR).append("/").append(std::to_string(--synced_shard_seq_no));
                    fs_mount->get_hash(prev_shard_hash_from_hpfs, hpfs::RW_SESSION_NAME, prev_shard_vpath);
                }

                if (prev_shard_hash_from_file != util::h32_empty               // Hash in the prev_shard.hash of the 0th shard is h32 empty. Syncing should be stopped then.
                    && prev_shard_hash_from_file != prev_shard_hash_from_hpfs) // Continue to sync backwards if the hash from prev_shard.hash is not matching with the shard hash from hpfs.
                {
                    const std::string shard_path = std::string(RAW_DIR).append("/").append(std::to_string(synced_shard_seq_no));
                    set_target_push_back(hpfs::sync_target{prev_shard_hash_from_file, shard_path, hpfs::BACKLOG_ITEM_TYPE::DIR});
                }
                else
                {
                    // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                    remove_old_shards(ctx.get_lcl_id().seq_no, RAW_SHARD_SIZE, conf::cfg.node.history_config.max_raw_shards, RAW_DIR);
                }
            }
            else
            {
                // When there are no more shards to sync, Remove old shards that exceeds max shard range.
                remove_old_shards(ctx.get_lcl_id().seq_no, RAW_SHARD_SIZE, conf::cfg.node.history_config.max_raw_shards, RAW_DIR);
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

    void ledger_sync::on_sync_target_abandoned()
    {
        // Reset these flags since we are abandoning the sync.
        is_last_primary_shard_syncing = false;
        is_last_raw_shard_syncing = false;
    }

} // namespace ledger