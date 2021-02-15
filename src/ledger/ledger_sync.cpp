
#include "./ledger_sync.hpp"
#include "ledger.hpp"

namespace ledger
{
    constexpr const char *HPFS_SESSION_NAME = "ro_shard_sync_status";

    void ledger_sync::on_sync_complete(const hpfs::sync_target &last_sync_target)
    {
        const std::string session_name = "sync_read_session";
        fs_mount->start_ro_session(session_name, true);
        const std::string shard_hash_file_path = fs_mount->physical_path(session_name, last_sync_target.vpath) + PREV_SHARD_HASH_FILENAME;
        const int fd = open(shard_hash_file_path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd == -1)
        {
            LOG_DEBUG << "Cannot read " << shard_hash_file_path;
            return;
        }

        util::h32 prev_shard_hash_from_file;
        const int res = read(fd, &prev_shard_hash_from_file, sizeof(util::h32));
        close(fd);
        if (res == -1)
        {
            LOG_ERROR << errno << ": Error reading hash file. " << shard_hash_file_path;
            return;
        }
        util::h32 prev_shard_hash_from_hpfs;
        const size_t pos = last_sync_target.vpath.find_last_of("/");
        if (pos == std::string::npos)
        {
            LOG_ERROR << "Error retreiving shard no from " << last_sync_target.vpath;
            return;
        }
        const std::string shard_seq_no_str = last_sync_target.vpath.substr(pos + 1);
        uint64_t shard_seq_no;
        if (util::stoull(shard_seq_no_str, shard_seq_no) == -1)
        {
            LOG_ERROR << "Error converting shard no from string. " << shard_seq_no_str;
            return;
        }
        const std::string prev_shard_vpath = std::string(PRIMARY_DIR).append("/").append(std::to_string(--shard_seq_no));
        fs_mount->get_hash(prev_shard_hash_from_hpfs, session_name, prev_shard_vpath);

        if (prev_shard_hash_from_file != util::h32_empty && prev_shard_hash_from_file != prev_shard_hash_from_hpfs)
        {
            std::list<hpfs::sync_target> sync_target_list;
            // We first request the latest shard.
            const std::string sync_name = "shard " + std::to_string(shard_seq_no);
            const std::string shard_path = std::string(PRIMARY_DIR).append("/").append(std::to_string(shard_seq_no));
            sync_target_list.push_back(hpfs::sync_target{sync_name, prev_shard_hash_from_file, shard_path, hpfs::BACKLOG_ITEM_TYPE::DIR});
            // Set sync targets for ledger fs.
            ledger::ledger_sync_worker.set_target(std::move(sync_target_list));
        }
        // else
        // {
        is_ledger_shard_desync = false;
        get_last_ledger();
        // }

        fs_mount->stop_ro_session(session_name);
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

} // namespace ledger