#ifndef _HP_STATUS_
#define _HP_STATUS_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"
#include "ledger/ledger_common.hpp"

namespace status
{
    void init(const p2p::sequence_hash &lcl_id, const ledger::ledger_record &ledger);

    void ledger_created(const p2p::sequence_hash &lcl_id, const ledger::ledger_record &ledger);

    void sync_status_changed(const bool in_sync);

} // namespace status

#endif
