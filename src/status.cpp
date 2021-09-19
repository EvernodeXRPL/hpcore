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

    // Indicates the current voting status.
    std::atomic<VOTE_STATUS> vote_status = VOTE_STATUS::UNKNOWN;

    std::shared_mutex unl_mutex;
    std::set<std::string> unl; // List of last reported unl binary pubkeys.

    std::shared_mutex peers_mutex;
    std::set<conf::peer_ip_port> peers; // Known ip:port pairs for connection verified peers.
    std::atomic<size_t> peer_count = 0;
    std::atomic<bool> weakly_connected = false;
    std::atomic<int16_t> available_mesh_capacity = -1;

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
        vote_status_changed(VOTE_STATUS::SYNCED);

        std::unique_lock lock(ledger_mutex);
        lcl_id = ledger_id;
        last_ledger = ledger;
        event_queue.try_enqueue(ledger_created_event{ledger});
    }

    void vote_status_changed(const VOTE_STATUS new_status)
    {
        if (new_status != vote_status.load())
        {
            vote_status = new_status;
            event_queue.try_enqueue(vote_status_change_event{new_status});
        }
    }

    const util::sequence_hash get_lcl_id()
    {
        std::shared_lock lock(ledger_mutex);
        return lcl_id;
    }

    const VOTE_STATUS get_vote_status()
    {
        return vote_status.load();
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

            if (conf::cfg.health.connectivity_stats)
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

            if (conf::cfg.health.connectivity_stats)
                event_queue.try_enqueue(connectivity_health{peer_count.load(), weakly_connected.load()});
        }
    }

    const bool get_weakly_connected()
    {
        return weakly_connected.load();
    }

    void set_available_mesh_capacity(const int16_t new_capacity)
    {
        available_mesh_capacity = new_capacity;
    }

    const int16_t get_available_mesh_capacity()
    {
        return available_mesh_capacity.load();
    }

    //----- Node health

    void report_proposal_batch(const std::list<p2p::proposal> &proposals)
    {
        if (!conf::cfg.health.proposal_stats)
            return;

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
        if (!conf::cfg.health.proposal_stats)
            return;

        event_queue.try_enqueue(phealth);
    }

} // namespace status