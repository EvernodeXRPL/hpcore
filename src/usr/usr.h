#ifndef _HP_USR_H_
#define _HP_USR_H_

#define USER_CHALLENGE_LEN 16

#include <cstdio>
#include <vector>
#include <map>
#include "../shared.h"

using namespace std;
using namespace shared;

namespace usr
{
extern map<string, ContractUser> users;

int init();
void create_user_challenge(string &msg, string &challenge);
bool verify_user_challenge_response(string &response, string &original_challenge, string &extracted_pubkey);
void add_user(string &pubkeyb64);
void remove_user(string &pubkeyb64);

} // namespace usr

#endif