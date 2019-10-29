#ifndef _HP_CONS_LEDGER_H_
#define _HP_CONS_LEDGER_H_

#include "../p2p/p2p.hpp"

namespace cons
{

std::string save_ledger(const p2p::proposal &proposal);

void load_ledger();

}

#endif