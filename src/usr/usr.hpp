#ifndef _HP_USR_H_
#define _HP_USR_H_

#include <cstdio>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include "../util.hpp"
#include "../sock/socket_session.hpp"
#include "user_session_handler.hpp"

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
    // User binary public key
    std::string pubkey;

    // Holds the unprocessed user input collected from websocket.
    std::string inbuffer;

    // Holds the websocket session of this user.
    // We don't need to own the session object since the lifetime of user and session are coupled.
    sock::socket_session<user_outbound_message> *session;

    /**
     * @param _pubkey The public key of the user in binary format.
     */
    connected_user(sock::socket_session<user_outbound_message> *_session, std::string_view _pubkey)
    {
        session = _session;
        pubkey = _pubkey;
    }
};

/**
 * Connected (authenticated) user list. (Exposed to other sub systems)
 * Map key: User socket session id (<ip:port>)
 */
extern std::unordered_map<std::string, usr::connected_user> users;
extern std::mutex users_mutex; // Mutex for users access race conditions.

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

void create_user_challenge(std::string &msg, std::string &challengehex);

int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge);

int add_user(sock::socket_session<user_outbound_message> *session, const std::string &pubkey);

int remove_user(const std::string &sessionid);

void start_listening();

void stop_listening();

} // namespace usr

#endif