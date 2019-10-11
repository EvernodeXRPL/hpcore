#ifndef _HP_USR_H_
#define _HP_USR_H_

#include <cstdio>
#include <vector>
#include <map>
#include "../util.hpp"

/**
 * Maintains the global user list with pending input outputs and manages user connections.
 */
namespace usr
{

/**
 * Global authenticated (challenge-verified) user list.
 */
extern std::map<std::string, util::contract_user> users;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 */
extern std::map<std::string, std::string> pending_challenges;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 */
extern std::map<std::string, std::string> pending_challenges;

int init();

void create_user_challenge(std::string &msg, std::string &challengeb64);

int verify_user_challenge_response(std::string &extracted_pubkeyb64, const std::string &response, const std::string &original_challenge);

int add_user(const std::string &sessionid, const std::string &pubkeyb64);

int remove_user(const std::string &sessionid);

int read_contract_user_outputs();

void start_listening();

} // namespace usr

#endif