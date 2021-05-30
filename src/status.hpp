#ifndef _HP_STATUS_
#define _HP_STATUS_

#include "pchheader.hpp"
#include "util/sequence_hash.hpp"
#include "ledger/ledger_common.hpp"

namespace status
{
    void init_ledger(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger);

    void init_unl(const std::set<std::string> &init_unl);

    void ledger_created(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger);

    void sync_status_changed(const bool in_sync);

    void unl_changed(const std::set<std::string> &new_unl);

} // namespace status

#endif
