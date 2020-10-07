#ifndef _HP_LEDGER_
#define _HP_LEDGER_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"

namespace ledger
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";

    struct ledger_cache_entry
    {
        std::string lcl;
        std::string state;
    };

    struct ledger_context
    {
        std::string lcl;
        uint64_t led_seq_no = 0;
        std::string last_requested_lcl;

        // Map of closed ledgers(only lrdgername[sequnece_number-hash], state hash) with sequence number as map key.
        // Contains closed ledgers from oldest to latest - MAX_LEDGER_SEQUENCE.
        // This is loaded when node started and updated throughout consensus - delete ledgers that falls behind MAX_LEDGER_SEQUENCE range.
        std::map<uint64_t, ledger_cache_entry> cache;
    };

    extern ledger_context ctx;

    int init();

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_ledgers(const uint64_t led_seq_no);

    int write_ledger_contents(const std::string &file_name, const char *ledger_raw, const size_t ledger_size);

    void remove_ledger(const std::string &file_name);

    void send_ledger_history_request(const std::string &minimum_lcl, const std::string &required_lcl);

    bool check_required_lcl_availability(const p2p::history_request &hr);

    const p2p::history_response retrieve_ledger_history(const p2p::history_request &hr);

    void handle_ledger_history_response(const p2p::history_response &hr);

} // namespace ledger

#endif