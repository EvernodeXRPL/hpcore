#include "../p2p/p2p.hpp"
#include "sqlite.hpp"
#include "ledger_sync.hpp"
#include "ledger_mount.hpp"

namespace ledger::ledger_sample
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";
    constexpr const char *DATEBASE = "ledger.sqlite";
    constexpr const char *SHARD_INDEX = "shard.idx";
    constexpr uint8_t SHARD_SIZE = 4;
    constexpr int FILE_PERMS = 0644;

    struct ledger_context
    {
        sqlite3 *db = NULL;
        std::string hpfs_session_name;
    };

    extern ledger_context ctx;
    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_shards(const uint64_t &led_shard_no);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);

    int update_shard_index(const uint64_t &shard_no, std::string_view shard_path);

    int read_shard_index(util::h32 &shard_hash, const uint64_t &shard_no);

    int read_shard_index(std::string &shard_hashes);

    int start_hpfs_session(ledger_context &ctx);

    int stop_hpfs_session(ledger_context &ctx);

} // namespace ledger::ledger_sample