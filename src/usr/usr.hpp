#ifndef _HP_USR_H_
#define _HP_USR_H_

#include <cstdio>
#include <vector>
#include <map>
#include "../util.hpp"

using namespace std;
using namespace util;

/**
 * Maintains the global user list with pending input outputs and manages user connections.
 */
namespace usr
{

/**
 * Global authenticated (challenge-verified) user list.
 */
extern map<string, contract_user> users;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 */
extern map<string, string> pending_challenges;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 */
extern map<string, string> pending_challenges;

int init();

void create_user_challenge(string &msg, string &challengeb64);

int verify_user_challenge_response(const string &response, const string &original_challenge, string &extracted_pubkey);

int add_user(const string &sessionid, const string &pubkeyb64);

int remove_user(const string &sessionid);

int read_contract_user_outputs();

void start_listening();

} // namespace usr

#endif