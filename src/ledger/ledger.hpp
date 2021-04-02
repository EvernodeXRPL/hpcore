#ifndef _HP_LEDGER_LEDGER_
#define _HP_LEDGER_LEDGER_

#include "../p2p/p2p.hpp"
#include "sqlite.hpp"
#include "../consensus.hpp"
#include "ledger_sync.hpp"
#include "ledger_mount.hpp"

namespace ledger
{
    struct ledger_context
    {
    private:
        std::shared_mutex lcl_mutex;
        p2p::sequence_hash lcl_id;
        std::shared_mutex last_primary_shard_mutex;
        p2p::sequence_hash last_primary_shard_id;
        std::shared_mutex last_blob_shard_mutex;
        p2p::sequence_hash last_blob_shard_id;

    public:
        // These flags will be marked as true after doing the shards cleanup and requesting
        // at the first consensus round to align with the max shard counts.
        std::atomic<bool> primary_shards_persisted = false;
        std::atomic<bool> blob_shards_persisted = false;

        const p2p::sequence_hash get_lcl_id()
        {
            std::shared_lock lock(lcl_mutex);
            return lcl_id;
        }

        void set_lcl_id(const p2p::sequence_hash &sequence_hash_id)
        {
            std::unique_lock lock(lcl_mutex);
            lcl_id = sequence_hash_id;
        }

        const p2p::sequence_hash get_last_primary_shard_id()
        {
            std::shared_lock lock(last_primary_shard_mutex);
            return last_primary_shard_id;
        }

        void set_last_primary_shard_id(const p2p::sequence_hash &sequence_hash_id)
        {
            std::unique_lock lock(last_primary_shard_mutex);
            last_primary_shard_id = sequence_hash_id;
        }

        const p2p::sequence_hash get_last_blob_shard_id()
        {
            std::shared_lock lock(last_blob_shard_mutex);
            return last_blob_shard_id;
        }

        void set_last_blob_shard_id(const p2p::sequence_hash &sequence_hash_id)
        {
            std::unique_lock lock(last_blob_shard_mutex);
            last_blob_shard_id = sequence_hash_id;
        }
    };

    extern ledger_context ctx;
    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int save_ledger(const p2p::proposal &proposal, const consensus::consensed_user_map &consensed_users,
                    const std::map<std::string, consensus::generated_user_output> &generated_user_outputs);

    int prepare_shard(sqlite3 **db, uint64_t &shard_seq_no, const uint64_t ledger_seq_no);

    int save_ledger_blob(std::string_view ledger_hash, const consensus::consensed_user_map &consensed_users,
                         const std::map<std::string, consensus::generated_user_output> &generated_user_outputs);

    void remove_old_shards(const uint64_t led_shard_no, std::string_view shard_parent_dir);

    void persist_shard_history(const uint64_t shard_seq_no, std::string_view shard_parent_dir);

    int get_last_ledger_and_update_context(std::string_view session_name, const p2p::sequence_hash &last_primary_shard_id);

    int get_last_shard_info(std::string_view session_name, p2p::sequence_hash &last_shard_id, const std::string &shard_parent_dir);

    int persist_max_shard_seq_no(const std::string &shard_parent_dir, const uint64_t last_shard_seq_no);

    int get_root_hash_from_ledger(util::h32 &root_hash, const uint64_t seq_no);

} // namespace ledger

#endif
