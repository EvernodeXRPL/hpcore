#include "../p2p/p2p.hpp"
#include "sqlite.hpp"
#include "ledger_sync.hpp"
#include "ledger_mount.hpp"

namespace ledger
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";
    constexpr const char *DATEBASE = "ledger.sqlite";
    constexpr uint8_t SHARD_SIZE = 4;
    constexpr int FILE_PERMS = 0644;

    struct ledger_context
    {
    private:
        std::string lcl;
        uint64_t seq_no = 0;
        uint64_t shard_seq_no = 0;
        util::h32 last_shard_hash = util::h32_empty;
        std::shared_mutex lcl_mutex;
        std::shared_mutex shard_mutex;

    public:
        sqlite3 *db = NULL;
        std::string hpfs_session_name;

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

        const uint64_t get_shard_seq_no()
        {
            std::shared_lock lock(shard_mutex);
            return shard_seq_no;
        }

        const util::h32 get_last_shard_hash()
        {
            std::shared_lock lock(shard_mutex);
            return last_shard_hash;
        }

        void set_last_shard_hash(const uint64_t new_shard_seq_no, const util::h32 &new_last_shard_hash)
        {
            std::unique_lock lock(shard_mutex);
            shard_seq_no = new_shard_seq_no;
            last_shard_hash = new_last_shard_hash;
        }
    };

    extern ledger_context ctx;
    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_shards(const uint64_t led_shard_no);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);

    int get_last_ledger();

    int get_last_shard_info(std::string_view session_name, util::h32 &last_shard_hash, uint64_t &shard_seq_no);

    int start_hpfs_session(ledger_context &ctx);

    int stop_hpfs_session(ledger_context &ctx);

} // namespace ledger