#ifndef _HP_STATUS_
#define _HP_STATUS_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"
#include "ledger/ledger_common.hpp"

namespace status
{
    void init_ledger(const p2p::sequence_hash &ledger_id, const ledger::ledger_record &ledger);

    void init_unl(const std::set<std::string> &init_unl);

    void ledger_created(const p2p::sequence_hash &ledger_id, const ledger::ledger_record &ledger);

    void sync_status_changed(const bool in_sync);

    void unl_changed(const std::set<std::string> &new_unl);

} // namespace status

#endif
