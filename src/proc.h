#ifndef _HP_PROC_H_
#define _HP_PROC_H_

#include <cstdio>
#include <vector>
#include <map>

using namespace std;

namespace proc
{

struct ProcInfo
{
    int requestpipe[2];
    int replypipe[2];
};

extern map<int, ProcInfo> pidmap;

struct ContractUser
{
    int fdin;
    int fdout;
};

struct ContractInputMsg
{
    string hpversion;
    vector<ContractUser> users;
};

int exec_contract();
void read_contract_outputs();

} // namespace proc

#endif