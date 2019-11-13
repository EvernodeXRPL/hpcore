#ifndef _HP_CONS_LEDGER_
#define _HP_CONS_LEDGER_

#include "../p2p/p2p.hpp"

namespace cons
{

struct ledger_history
{
    std::string lcl;
    uint64_t led_seq_no;
};

extern std::string last_requested_lcl;

const std::string save_ledger(const p2p::proposal &proposal, const uint64_t led_seq_no);

void write_ledger(uint64_t led_seq_no, const std::string &lcl_hash, const char *ledger_raw, size_t ledger_size);

const ledger_history load_ledger();

void send_ledger_history_request(const std::string &lcl);

const p2p::history_response retrieve_ledger_history(const p2p::history_request &hr);

void send_ledger_history(std::string peer_session_id, const p2p::history_request &hr);

}

#endif