#ifndef _HP_LEDGER_LEDGER_
#define _HP_LEDGER_LEDGER_

#include "../p2p/p2p.hpp"
#include "sqlite.hpp"
#include "../consensus.hpp"
#include "ledger_sync.hpp"
#include "ledger_mount.hpp"

namespace ledger
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";
    constexpr const char *DATEBASE = "ledger.sqlite";
    constexpr uint64_t PRIMARY_SHARD_SIZE = 4;
    constexpr uint64_t BLOB_SHARD_SIZE = 4;
    constexpr int FILE_PERMS = 0644;
    constexpr uint64_t MAX_BLOB_SHARDS = 4;

    struct ledger_context
    {
    private:
        std::string lcl;
        uint64_t seq_no = 0;
        uint64_t primary_shard_seq_no = 0;
        util::h32 last_primary_shard_hash = util::h32_empty;
        uint64_t blob_shard_seq_no = 0;
        util::h32 last_blob_shard_hash = util::h32_empty;
        std::shared_mutex lcl_mutex;
        std::shared_mutex primary_shard_mutex;
        std::shared_mutex blob_shard_mutex;

    public:
        const std::string get_lcl()
        {
            std::shared_lock lock(lcl_mutex);
            return lcl;
        }

        uint64_t get_seq_no()
        {
            std::shared_lock lock(lcl_mutex);
            return seq_no;
        }

        void set_lcl(const uint64_t new_seq_no, std::string_view new_lcl)
        {
            std::unique_lock lock(lcl_mutex);
            lcl = new_lcl;
            seq_no = new_seq_no;
        }

        const uint64_t get_primary_shard_seq_no()
        {
            std::shared_lock lock(primary_shard_mutex);
            return primary_shard_seq_no;
        }

        const util::h32 get_last_primary_shard_hash()
        {
            std::shared_lock lock(primary_shard_mutex);
            return last_primary_shard_hash;
        }

        void set_last_primary_shard_hash(const uint64_t new_shard_seq_no, const util::h32 &new_last_shard_hash)
        {
            std::unique_lock lock(primary_shard_mutex);
            primary_shard_seq_no = new_shard_seq_no;
            last_primary_shard_hash = new_last_shard_hash;
        }

        const uint64_t get_blob_shard_seq_no()
        {
            std::shared_lock lock(blob_shard_mutex);
            return blob_shard_seq_no;
        }

        const util::h32 get_last_blob_shard_hash()
        {
            std::shared_lock lock(blob_shard_mutex);
            return last_blob_shard_hash;
        }

        void set_last_blob_shard_hash(const uint64_t new_blob_shard_seq_no, const util::h32 &new_last_blob_shard_hash)
        {
            std::unique_lock lock(blob_shard_mutex);
            blob_shard_seq_no = new_blob_shard_seq_no;
            last_blob_shard_hash = new_last_blob_shard_hash;
        }
    };

    struct ledger_blob
    {
        std::string ledger_hash;
        std::map<std::string, std::vector<std::string>> inputs;
        std::map<std::string, std::vector<std::string>> outputs;
    };

    extern ledger_context ctx;
    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int save_ledger(const p2p::proposal &proposal, const std::map<std::string, consensus::candidate_user_input> &candidate_user_inputs,
                    const std::map<std::string, consensus::generated_user_output> &generated_user_outputs);

    int prepare_shard(sqlite3 **db, uint64_t &shard_seq_no, const uint64_t ledger_seq_no);

    int save_ledger_blob(std::string_view ledger_hash, const std::map<std::string, consensus::candidate_user_input> &candidate_user_inputs,
                         const std::map<std::string, consensus::generated_user_output> &generated_user_outputs);

    void remove_old_shards(const uint64_t led_shard_no, std::string_view shard_parent_dir);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);

    int get_last_ledger_and_update_context();

    int get_last_shard_info(std::string_view session_name, util::h32 &last_primary_shard_hash, uint64_t &primary_shard_seq_no, std::string_view shard_parent_dir);

} // namespace ledger

#endif
