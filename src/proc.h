#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <vector>
#include <map>

using namespace std;

namespace proc
{

struct ContractUser
{
    string pubkeyb64;
    int inpipe[2]; //from User to Contract
    int outpipe[2]; //from Contract to User
};

struct ContractInputMsg
{
    vector<ContractUser> users;
};

struct ProcInfo
{
    vector<ContractUser> users;
};

extern map<int, ProcInfo> pidmap;

int exec_contract(ContractInputMsg &msg);
void read_contract_outputs();

} // namespace proc

#endif