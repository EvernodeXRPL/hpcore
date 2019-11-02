#ifndef _HP_USR_
#define _HP_USR_

#include "../pchheader.hpp"
#include "../util.hpp"
#include "../sock/socket_session.hpp"
#include "user_session_handler.hpp"
#include "user_input.hpp"

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
    const std::string pubkey;

    // Holds the unprocessed user inputs collected from websocket.
    std::list<user_submitted_message> submitted_inputs;

    // Holds the websocket session of this user.
    // We don't need to own the session object since the lifetime of user and session are coupled.
    sock::socket_session<user_outbound_message> *session;

    /**
     * @param session The web socket session the user is connected to.
     * @param pubkey The public key of the user in binary format.
     */
    connected_user(sock::socket_session<user_outbound_message> *session, std::string_view pubkey)
        : pubkey(pubkey)
    {
        this->session = session;
    }
};

/**
 * The context struct to hold global connected-users and related objects.
 */
struct connected_context
{
    // Connected (authenticated) user list.
    // Map key: User socket session id (<ip:port>)
    std::unordered_map<std::string, usr::connected_user> users;
    std::mutex users_mutex; // Mutex for users access race conditions.

    // Holds set of connected user session ids and public keys for lookups.
    // This is used for pubkey duplicate checks as well.
    // Map key: User binary pubkey
    std::unordered_map<std::string, const std::string> sessionids;

    // Keep track of verification-pending challenges issued to newly connected users.
    // Map key: User socket session id (<ip:port>)
    std::unordered_map<std::string, const std::string> pending_challenges;
};
extern connected_context ctx;

/**
 * Struct to hold objects used by socket listener.
 */
struct listener_context
{
    // The SSL context holds certificates to facilitate TLS connections.
    ssl::context ssl_ctx{ssl::context::tlsv13};

    // User session handler instance. This instance's methods will be fired for any user socket activity.
    usr::user_session_handler global_usr_session_handler;

    // The IO context used by the websocket listener. (not exposed out of this namespace)
    net::io_context ioc;

    // The thread the websocket listener is running on. (not exposed out of this namespace)
    std::thread listener_thread;

    // Used to pass down the default settings to the socket session
    sock::session_options sess_opts;
};

int init();

std::string issue_challenge(const std::string sessionid);

int verify_challenge(std::string_view message, sock::socket_session<user_outbound_message> *session);

int handle_user_message(connected_user &user, std::string_view message);

int add_user(sock::socket_session<user_outbound_message> *session, const std::string &pubkey);

int remove_user(const std::string &sessionid);

void start_listening();

} // namespace usr

#endif