#include "../p2p/p2p.hpp"
#include "sqlite.hpp"

namespace ledger::ledger_sample
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";
    // When ledger fs is implemented we can make make "/ledger_temp/primary" -> "/primary"
    constexpr const char *PRIMARY_DIR_PATH = "/ledger_temp/primary";
    constexpr const char *DATEBASE = "ledger.sqlite";
    constexpr uint8_t SHARD_SIZE = 4;

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_shards(const uint64_t led_shard_no);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);

} // namespace ledger::ledger_sample