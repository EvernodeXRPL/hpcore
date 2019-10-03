#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <map>
#include "shared.h"

using namespace std;
using namespace shared;

namespace proc
{

struct ContractExecArgs
{
    map<string, ContractUser> *users;

    //ContractExecArgs(map<string, ContractUser> &_users)
};

int exec_contract(ContractExecArgs &args);
bool is_contract_running();

} // namespace proc

#endif