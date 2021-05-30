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
        util::sequence_hash lcl_id;
        std::shared_mutex last_primary_shard_mutex;
        util::sequence_hash last_primary_shard_id;
        std::shared_mutex last_raw_shard_mutex;
        util::sequence_hash last_raw_shard_id;

    public:
        // These flags will be marked as true after doing the shards cleanup and requesting
        // at the first consensus round to align with the max shard counts.
        std::atomic<bool> primary_shards_persisted = false;
        std::atomic<bool> raw_shards_persisted = false;

        const util::sequence_hash get_lcl_id()
        {
            std::shared_lock lock(lcl_mutex);
            return lcl_id;
        }

        void set_lcl_id(const util::sequence_hash &sequence_hash_id)
        {
            std::unique_lock lock(lcl_mutex);
            lcl_id = sequence_hash_id;
        }

        const util::sequence_hash get_last_primary_shard_id()
        {
            std::shared_lock lock(last_primary_shard_mutex);
            return last_primary_shard_id;
        }

        void set_last_primary_shard_id(const util::sequence_hash &sequence_hash_id)
        {
            std::unique_lock lock(last_primary_shard_mutex);
            last_primary_shard_id = sequence_hash_id;
        }

        const util::sequence_hash get_last_raw_shard_id()
        {
            std::shared_lock lock(last_raw_shard_mutex);
            return last_raw_shard_id;
        }

        void set_last_raw_shard_id(const util::sequence_hash &sequence_hash_id)
        {
            std::unique_lock lock(last_raw_shard_mutex);
            last_raw_shard_id = sequence_hash_id;
        }
    };

    extern ledger_context ctx;
    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int update_ledger(const p2p::proposal &proposal, const consensus::consensed_user_map &consensed_users);

    int update_primary_ledger(const p2p::proposal &proposal, const consensus::consensed_user_map &consensed_users, util::sequence_hash &new_lcl_id);

    int update_ledger_raw_data(const p2p::proposal &proposal, const consensus::consensed_user_map &consensed_users, const util::sequence_hash &lcl_id);

    int insert_ledger_record(sqlite3 *db, const util::sequence_hash &current_lcl_id, const uint64_t shard_seq_no,
                             const p2p::proposal &proposal, util::sequence_hash &new_lcl_id, ledger_record &ledger);

    int insert_raw_data_records(sqlite3 *db, const uint64_t shard_seq_no, const p2p::proposal &proposal,
                                const consensus::consensed_user_map &consensed_users, const util::sequence_hash &lcl_id);

    int create_raw_data_blob_file(const std::string &shard_path, const char *file_name, size_t &file_size);

    int prepare_shard(sqlite3 **db, uint64_t &shard_seq_no, const uint64_t ledger_seq_no, const uint64_t shard_size,
                      const char *shard_dir, const char *db_name, const bool keep_db_connection);

    void remove_old_shards(const uint64_t lcl_seq_no, const uint64_t shard_size, const uint64_t max_shards, std::string_view shard_parent_dir);

    void persist_shard_history(const uint64_t shard_seq_no, std::string_view shard_parent_dir);

    int get_last_ledger_and_update_context(std::string_view session_name, const util::sequence_hash &last_primary_shard_id, const bool genesis_fallback);

    int get_last_shard_info(std::string_view session_name, util::sequence_hash &last_shard_id, const std::string &shard_parent_dir);

    int persist_max_shard_seq_no(const std::string &shard_parent_dir, const uint64_t last_shard_seq_no);

    int get_root_hash_from_ledger(util::h32 &root_hash, const uint64_t seq_no);

} // namespace ledger

#endif
