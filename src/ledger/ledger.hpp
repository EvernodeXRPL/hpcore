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
        std::shared_mutex lcl_mutex;

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
    };

    extern ledger_context ctx;
    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_shards(const uint64_t led_shard_no);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);

    int update_shard_index(const uint64_t shard_no);

    int read_shard_index(std::string_view session_name, util::h32 &shard_hash, const uint64_t shard_no);

    int read_shard_index(std::string_view session_name, std::string &shard_hashes);

    int read_shards_from_given_shard_no(std::string_view session_name, std::map<uint64_t, util::h32> &shard_hash_list, uint64_t shard_no);

    int get_last_ledger();

    int start_hpfs_session(ledger_context &ctx);

    int stop_hpfs_session(ledger_context &ctx);

} // namespace ledger