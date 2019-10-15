#ifndef _HP_USR_H_
#define _HP_USR_H_

#include <cstdio>
#include <string_view>
#include <unordered_map>
#include "../util.hpp"

/**
 * Maintains the global user list with pending input outputs and manages user connections.
 */
namespace usr
{

/**
 * Holds information about an authenticated (challenge-verified) user
 * connected to the HotPocket node.
 */
struct connected_user
{
    // Base64 user public key
    std::string pubkeyb64;
    
    // Holds the unprocessed user input collected from websocket.
    std::string inbuffer;

    connected_user(std::string_view _pubkeyb64)
    {
        pubkeyb64 = _pubkeyb64;
    }
};

/**
 * Global authenticated (challenge-verified) user list.
 */
extern std::unordered_map<std::string, usr::connected_user> users;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 * Map key: User socket session id (<ip:port>)
 */
extern std::unordered_map<std::string, std::string> sessionids;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 */
extern std::unordered_map<std::string, std::string> pending_challenges;

int init();

void deinit();

void create_user_challenge(std::string &msg, std::string &challengeb64);

int verify_user_challenge_response(std::string &extracted_pubkeyb64, std::string_view response, std::string_view original_challenge);

int add_user(const std::string &sessionid, const std::string &pubkeyb64);

int remove_user(const std::string &sessionid);

void start_listening();

void stop_listening();

} // namespace usr

#endif