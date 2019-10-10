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

// Length of user random challenge bytes.
static const int user_challenge_len = 16;

// Message type for the user challenge.
static const char *msg_public_challenge = "public_challenge";

// Message type for the user challenge response.
static const char *msg_challenge_resp = "challenge_response";

/**
 * Global authenticated (challenge-verified) user list.
 */
extern map<string, contract_user> users;

int init();

void create_user_challenge(string &msg, string &challengeb64);

int verify_user_challenge_response(const string &response, const string &original_challenge, string &extracted_pubkey);

int add_user(const string &pubkeyb64);

int remove_user(const string &pubkeyb64);

int read_contract_user_outputs();

} // namespace usr

#endif