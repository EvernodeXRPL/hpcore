#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <vector>

using namespace std;

namespace proc
{

struct ContractUser
{
    string pubkeyb64;
    int inpipe[2];  //from User to Contract
    int outpipe[2]; //from Contract to User
};

struct ContractExecArgs
{
    vector<ContractUser> users;
};

int exec_contract(ContractExecArgs &msg);
int read_contract_outputs(vector<ContractUser> users);
bool is_contract_running();

} // namespace proc

#endif