
#include "./ledger_sync.hpp"
#include "ledger.hpp"

namespace ledger
{
    constexpr const char *HPFS_SESSION_NAME = "ro_shard_sync_status";

    void ledger_sync::on_sync_complete(const hpfs::sync_target &last_sync_target)
    {
        if (last_sync_target.vpath == hpfs::LEDGER_PRIMARY_SHARD_INDEX_PATH)
        {
            check_shard_sync_status();
            fs_mount->set_parent_hash(last_sync_target.vpath, last_sync_target.hash);
        }
        else
        {
            LOG_INFO << "Hpfs " << name << " sync: All parents synced.";
            is_ledger_shard_desync = false;
            get_last_ledger();
        }
    }

    void ledger_sync::on_sync_abandoned()
    {
        // Reset shard sync status.
        is_ledger_shard_desync = false;
    }

    void ledger_sync::swap_collected_responses()
    {
        std::scoped_lock lock(p2p::ctx.collected_msgs.ledger_hpfs_responses_mutex);

        // Move collected hpfs responses over to local candidate responses list.
        if (!p2p::ctx.collected_msgs.ledger_hpfs_responses.empty())
            candidate_hpfs_responses.splice(candidate_hpfs_responses.end(), p2p::ctx.collected_msgs.ledger_hpfs_responses);
    }

    /**
     * Check shard sync status after the primary shard index file sync is complete and start necessary syncing for shards.
    */
    void ledger_sync::check_shard_sync_status()
    {
        fs_mount->start_ro_session(HPFS_SESSION_NAME, true);
        std::list<std::string> list = util::fetch_dir_entries(fs_mount->physical_path(HPFS_SESSION_NAME, hpfs::LEDGER_PRIMARY_DIR));
        // Check for the availability of the shard.idx file.
        if (std::find(list.begin(), list.end(), hpfs::LEDGER_SHARD_INDEX) != list.end())
        {
            list.erase(std::find(list.begin(), list.end(), hpfs::LEDGER_SHARD_INDEX));
            std::vector<uint64_t> seq_no_list;
            for (const std::string &entry : list)
            {
                uint64_t seq_no;
                if (util::stoull(entry, seq_no) == -1)
                {
                    break;
                }
                seq_no_list.push_back(seq_no);
            }
            std::sort(seq_no_list.begin(), seq_no_list.end());
            std::map<uint64_t, util::h32> out_of_sync_shard_list;
            for (const uint64_t entry : seq_no_list)
            {
                util::h32 expected_hash;
                read_shard_index(HPFS_SESSION_NAME, expected_hash, entry);
                util::h32 folder_hash;
                std::string path = std::string(hpfs::LEDGER_PRIMARY_DIR).append("/").append(std::to_string(entry));
                fs_mount->get_hash(folder_hash, HPFS_SESSION_NAME, path);
                if (expected_hash != util::h32_empty && expected_hash != folder_hash)
                {
                    out_of_sync_shard_list.try_emplace(entry, expected_hash);
                }
            }
            if (read_shards_from_given_shard_no(HPFS_SESSION_NAME, out_of_sync_shard_list, seq_no_list.empty() ? 0 : seq_no_list.back() + 1) == -1)
            {
                LOG_ERROR << "Error reading shard idx file in shard sync.";
                fs_mount->stop_ro_session(HPFS_SESSION_NAME);
                return;
            }
            std::queue<hpfs::sync_target> sync_target_list;
            for (auto &[shard_no, hash] : out_of_sync_shard_list)
            {
                std::string name = ("shard " + std::to_string(shard_no));
                sync_target_list.push(hpfs::sync_target{name, hash, std::string(hpfs::LEDGER_PRIMARY_DIR).append("/").append(std::to_string(shard_no)), hpfs::BACKLOG_ITEM_TYPE::DIR});
            }
            if (!sync_target_list.empty())
            {
                conf::change_role(conf::ROLE::OBSERVER);
                set_target(sync_target_list);
            }
            else
            {
                is_ledger_shard_desync = false;
            }
        }
        else
        {
            is_ledger_shard_desync = false;
        }
        fs_mount->stop_ro_session(HPFS_SESSION_NAME);
    }
} // namespace ledger