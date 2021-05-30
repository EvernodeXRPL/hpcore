#include "status.hpp"
#include "p2p/p2p.hpp"
#include "ledger/ledger_common.hpp"

namespace status
{
    std::shared_mutex status_mutex;
    p2p::sequence_hash lcl_id;         // Last ledger id/hash pair.
    ledger::ledger_record last_ledger; // Last ledger record that the node created.
    std::set<std::string> unl;         // List of last reported unl binary pubkeys.
    bool is_in_sync = false;

    void init_ledger(const p2p::sequence_hash &ledger_id, const ledger::ledger_record &ledger)
    {
        // Not acquiring the mutex lock since this is called during startup only.
        lcl_id = ledger_id;
        last_ledger = ledger;
        is_in_sync = true;
    }

    void init_unl(const std::set<std::string> &init_unl)
    {
        // Not acquiring the mutex lock since this is called during startup only.
        unl = init_unl;
    }

    void ledger_created(const p2p::sequence_hash &ledger_id, const ledger::ledger_record &ledger)
    {
        std::unique_lock lock(status_mutex);
        lcl_id = ledger_id;
        last_ledger = ledger;
        is_in_sync = true; // Creating a ledger automatically means we are in sync.
    }

    void sync_status_changed(const bool in_sync)
    {
        std::unique_lock lock(status_mutex);
        is_in_sync = in_sync;
    }

    void unl_changed(const std::set<std::string> &new_unl)
    {
        std::unique_lock lock(status_mutex);
        unl = new_unl;
    }

} // namespace status