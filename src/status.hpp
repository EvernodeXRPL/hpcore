#ifndef _HP_STATUS_
#define _HP_STATUS_

#include "pchheader.hpp"
#include "util/sequence_hash.hpp"
#include "ledger/ledger_common.hpp"
#include "conf.hpp"
#include "p2p/p2p.hpp"

namespace status
{
    struct unl_change_event
    {
        std::set<std::string> unl;
    };

    struct ledger_created_event
    {
        ledger::ledger_record ledger;
    };

    struct sync_status_change_event
    {
        bool in_sync = false;
    };

    struct proposal_health
    {
        uint64_t comm_latency_min = 0;
        uint64_t comm_latency_max = 0;
        uint64_t comm_latency_avg = 0;
        uint64_t read_latency_min = 0;
        uint64_t read_latency_max = 0;
        uint64_t read_latency_avg = 0;
        uint64_t batch_size = 0;
    };

    struct connectivity_health
    {
        size_t peer_count = 0;
        bool is_weakly_connected = false;
    };

    typedef std::variant<proposal_health, connectivity_health> health_event;

    // Represents any kind of change that has happened in the node.
    typedef std::variant<unl_change_event, ledger_created_event, sync_status_change_event, health_event> change_event;

    extern moodycamel::ConcurrentQueue<change_event> event_queue;

    void init_ledger(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger);
    void ledger_created(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger);
    void sync_status_changed(const bool in_sync);
    const util::sequence_hash get_lcl_id();
    const bool is_in_sync();
    const ledger::ledger_record get_last_ledger();

    void init_unl(const std::set<std::string> &init_unl);
    void unl_changed(const std::set<std::string> &new_unl);
    const std::set<std::string> get_unl();

    void set_peers(const std::set<conf::peer_ip_port> &updated_peers);
    const std::set<conf::peer_ip_port> get_peers();
    const size_t get_peers_count();
    void set_weakly_connected(const bool is_weakly_connected);
    const bool get_weakly_connected();
    void set_available_mesh_capacity(const int16_t new_capacity);
    const int16_t get_available_mesh_capacity();

    void report_proposal_batch(const std::list<p2p::proposal> &proposals);
    void emit_proposal_health();

} // namespace status

#endif
