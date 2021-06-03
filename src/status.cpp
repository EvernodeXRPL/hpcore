#include "status.hpp"
#include "util/sequence_hash.hpp"
#include "ledger/ledger_common.hpp"
#include "conf.hpp"

namespace status
{
    std::shared_mutex ledger_mutex;
    util::sequence_hash lcl_id;        // Last ledger id/hash pair.
    ledger::ledger_record last_ledger; // Last ledger record that the node created.
    bool is_in_sync = false;           // Indicates whether this node is in sync with other nodes or not.

    std::shared_mutex unl_mutex;
    std::set<std::string> unl; // List of last reported unl binary pubkeys.

    std::shared_mutex peers_mutex;
    std::set<conf::peer_ip_port> peers; // Known ip:port pairs for connection verified peers.

    //----- Ledger status

    void init_ledger(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger)
    {
        // Not acquiring the mutex lock since this is called during startup only.
        lcl_id = ledger_id;
        last_ledger = ledger;
        is_in_sync = true;
    }

    void ledger_created(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger)
    {
        std::unique_lock lock(ledger_mutex);
        lcl_id = ledger_id;
        last_ledger = ledger;
        is_in_sync = true; // Creating a ledger automatically means we are in sync.
    }

    void sync_status_changed(const bool in_sync)
    {
        std::unique_lock lock(ledger_mutex);
        is_in_sync = in_sync;
    }

    const util::sequence_hash get_lcl_id()
    {
        std::shared_lock lock(ledger_mutex);
        return lcl_id;
    }

    //----- UNL status

    void init_unl(const std::set<std::string> &init_unl)
    {
        // Not acquiring the mutex lock since this is called during startup only.
        unl = init_unl;
    }

    void unl_changed(const std::set<std::string> &new_unl)
    {
        std::unique_lock lock(unl_mutex);
        unl = new_unl;
    }

    const std::set<std::string> get_unl()
    {
        std::shared_lock lock(unl_mutex);
        return unl;
    }

    //----- Peers status

    void set_peers(const std::set<conf::peer_ip_port> &updated_peers)
    {
        std::unique_lock lock(peers_mutex);
        peers = std::move(updated_peers);
    }

    const std::set<conf::peer_ip_port> get_peers()
    {
        std::unique_lock lock(peers_mutex);
        return peers;
    }

} // namespace status