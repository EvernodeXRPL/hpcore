#include "../p2p/p2p.hpp"
#include "sqlite.hpp"

namespace ledger::ledger_sample
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";

    int save_ledger(const p2p::proposal &proposal);

    int extract_lcl(const std::string &lcl, uint64_t &seq_no, std::string &hash);
    
} // namespace ledger::ledger_sample