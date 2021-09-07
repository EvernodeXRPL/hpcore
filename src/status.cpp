#include "status.hpp"
#include "util/sequence_hash.hpp"
#include "ledger/ledger_common.hpp"
#include "conf.hpp"
#include "p2p/p2p.hpp"

namespace status
{
    moodycamel::ConcurrentQueue<change_event> event_queue;

    std::shared_mutex ledger_mutex;
    util::sequence_hash lcl_id;        // Last ledger id/hash pair.
    ledger::ledger_record last_ledger; // Last ledger record that the node created.

    // Indicates whether this node is in sync with other nodes or not.
    // -1=unknown, 0=not-in-sync, 1=in-sync
    std::atomic<int> in_sync = -1;

    std::shared_mutex unl_mutex;
    std::set<std::string> unl; // List of last reported unl binary pubkeys.

    std::shared_mutex peers_mutex;
    std::set<conf::peer_ip_port> peers; // Known ip:port pairs for connection verified peers.
    std::atomic<size_t> peer_count = 0;

    std::atomic<bool> weakly_connected = false;

    proposal_health phealth = {};

    //----- Ledger status

    void init_ledger(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger)
    {
        // Not acquiring the mutex lock since this is called during startup only.
        lcl_id = ledger_id;
        last_ledger = ledger;
    }

    void ledger_created(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger)
    {
        // If currently not-in-sync, report it as in-sync when a ledger is created.
        if (in_sync != 1)
            sync_status_changed(true);

        std::unique_lock lock(ledger_mutex);
        lcl_id = ledger_id;
        last_ledger = ledger;
        event_queue.try_enqueue(ledger_created_event{ledger});
    }

    void sync_status_changed(const bool new_in_sync)
    {
        in_sync = new_in_sync ? 1 : 0;
        event_queue.try_enqueue(sync_status_change_event{new_in_sync});
    }

    const util::sequence_hash get_lcl_id()
    {
        std::shared_lock lock(ledger_mutex);
        return lcl_id;
    }

    const bool is_in_sync()
    {
        return in_sync == 1;
    }

    const ledger::ledger_record get_last_ledger()
    {
        std::shared_lock lock(ledger_mutex);
        return last_ledger;
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

        event_queue.try_enqueue(unl_change_event{unl});
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

        if (peers.size() != peer_count)
        {
            peer_count = peers.size();
            event_queue.try_enqueue(connectivity_health{peer_count.load(), weakly_connected.load()});
        }
    }

    const std::set<conf::peer_ip_port> get_peers()
    {
        std::unique_lock lock(peers_mutex);
        return peers;
    }

    const size_t get_peers_count()
    {
        return peer_count.load();
    }

    void set_weakly_connected(const bool is_weakly_connected)
    {
        if (weakly_connected.load() != is_weakly_connected)
        {
            weakly_connected = is_weakly_connected;
            event_queue.try_enqueue(connectivity_health{peer_count.load(), weakly_connected.load()});
        }
    }

    const bool get_weakly_connected()
    {
        return weakly_connected.load();
    }

    //----- Node health

    void report_proposal_batch(const std::list<p2p::proposal> &proposals)
    {
        phealth.comm_latency_min = UINT64_MAX;
        phealth.comm_latency_max = 0;
        phealth.comm_latency_avg = 0;
        phealth.read_latency_min = UINT64_MAX;
        phealth.read_latency_max = 0;
        phealth.read_latency_avg = 0;
        phealth.batch_size = proposals.size();

        if (phealth.batch_size == 0)
            return;

        const uint64_t now = util::get_epoch_milliseconds();
        uint64_t total_comm_latency = 0;
        uint64_t total_read_latency = 0;

        for (const p2p::proposal &p : proposals)
        {
            const uint64_t comm_latency = (p.sent_timestamp < p.recv_timestamp) ? (p.recv_timestamp - p.sent_timestamp) : 0;
            const uint64_t read_latency = now - p.recv_timestamp;

            total_comm_latency += comm_latency;
            total_read_latency += read_latency;

            if (comm_latency < phealth.comm_latency_min)
                phealth.comm_latency_min = comm_latency;

            if (comm_latency > phealth.comm_latency_max)
                phealth.comm_latency_max = comm_latency;

            if (read_latency < phealth.read_latency_min)
                phealth.read_latency_min = read_latency;

            if (read_latency > phealth.read_latency_max)
                phealth.read_latency_max = read_latency;
        }

        phealth.comm_latency_avg = total_comm_latency / phealth.batch_size;
        phealth.read_latency_avg = total_read_latency / phealth.batch_size;
    }

    void emit_proposal_health()
    {
        event_queue.try_enqueue(phealth);
    }

} // namespace status