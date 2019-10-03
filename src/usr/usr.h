#ifndef _HP_USR_H_
#define _HP_USR_H_

#include <cstdio>
#include <vector>
#include <map>
#include "../shared.h"

using namespace std;
using namespace shared;

namespace usr
{
extern map<string, ContractUser> users;
void add_user(string pubkeyb64);
void remove_user(string pubkeyb64);

} // namespace usr

#endif