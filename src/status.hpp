#ifndef _HP_STATUS_
#define _HP_STATUS_

#include "pchheader.hpp"
#include "util/sequence_hash.hpp"
#include "ledger/ledger_common.hpp"
#include "conf.hpp"

namespace status
{
    struct unl_change_event
    {
        std::set<std::string> unl;
    };

    // Represents any kind of change that has happened in the node.
    typedef std::variant<unl_change_event> change_event;

    extern moodycamel::ConcurrentQueue<change_event> event_queue;

    void init_ledger(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger);
    void ledger_created(const util::sequence_hash &ledger_id, const ledger::ledger_record &ledger);
    void sync_status_changed(const bool in_sync);
    const util::sequence_hash get_lcl_id();
    const bool is_in_sync();

    void init_unl(const std::set<std::string> &init_unl);
    void unl_changed(const std::set<std::string> &new_unl);
    const std::set<std::string> get_unl();

    void set_peers(const std::set<conf::peer_ip_port> &updated_peers);
    const std::set<conf::peer_ip_port> get_peers();

} // namespace status

#endif
