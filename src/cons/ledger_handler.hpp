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

const std::string save_ledger(const p2p::proposal &proposal, const uint64_t led_seq_no);

const ledger_history load_ledger();

void send_ledger_history_request(const std::string &lcl);

std::map<uint64_t,p2p::history_ledger> retrieve_ledger_history(const p2p::history_request &hr);

}

#endif