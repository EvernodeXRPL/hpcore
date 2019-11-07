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

std::string save_ledger(const p2p::proposal &proposal, const uint64_t led_seq_no);

ledger_history load_ledger();

}

#endif