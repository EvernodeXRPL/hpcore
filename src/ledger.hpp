#ifndef _HP_LEDGER_
#define _HP_LEDGER_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"

namespace ledger
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";

    struct ledger_context
    {
        std::string lcl;
        uint64_t led_seq_no = 0;
        std::string last_requested_lcl;

        // Map of closed ledgers (lcl string) with sequence number as map key.
        // Contains closed ledgers from oldest to latest - MAX_LEDGER_SEQUENCE.
        // This is loaded when node started and updated throughout consensus.
        // Deletes ledgers that falls behind MAX_LEDGER_SEQUENCE range.
        std::map<uint64_t, const std::string> cache;
    };

    extern ledger_context ctx;

    int init();

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_ledgers(const uint64_t led_seq_no);

    int read_ledger(std::string_view file_path, std::vector<uint8_t> &buffer);

    int write_ledger(const std::string &file_name, const uint8_t *ledger_raw, const size_t ledger_size);

    void remove_ledger(const std::string &file_name);

    void send_ledger_history_request(const std::string &minimum_lcl, const std::string &required_lcl);

    bool check_required_lcl_availability(const p2p::history_request &hr);

    int retrieve_ledger_history(const p2p::history_request &hr, p2p::history_response &history_response);

    void handle_ledger_history_response(const p2p::history_response &hr);

} // namespace ledger

#endif