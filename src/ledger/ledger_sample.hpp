#include "../p2p/p2p.hpp"
#include "sqlite.hpp"
#include "ledger_sync.hpp"
#include "ledger_mount.hpp"

namespace ledger::ledger_sample
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";

    extern ledger::ledger_mount ledger_fs;         // Global ledger file system instance.
    extern ledger::ledger_sync ledger_sync_worker; // Global ledger file system sync instance.

    int init();

    void deinit();

    int save_ledger(const p2p::proposal &proposal);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);

} // namespace ledger::ledger_sample