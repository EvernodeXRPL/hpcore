#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <boost/thread/thread.hpp>
#include "usr.hpp"
#include "user_session_handler.hpp"
#include "../sock/socket_server.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"

namespace usr
{

// The SSL context is required, and holds certificates
ssl::context ctx{ssl::context::tlsv13};

/**
 * Connected (authenticated) user list. (Exposed to other sub systems)
 * Map key: User socket session id (<ip:port>)
 */
std::unordered_map<std::string, usr::connected_user> users;
std::mutex users_mutex; // Mutex for users access race conditions.

/**
 * Holds set of connected user session ids and public keys for lookups.
 * This is used for pubkey duplicate checks as well.
 * Map key: User binary pubkey
 */
std::unordered_map<std::string, const std::string> sessionids;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 * Map key: User socket session id (<ip:port>)
 */
std::unordered_map<std::string, const std::string> pending_challenges;

/**
 * User session handler instance. This instance's methods will be fired for any user socket activity.
 */
usr::user_session_handler global_usr_session_handler;

/**
 * The IO context used by the websocket listener. (not exposed out of this namespace)
 */
net::io_context ioc;

/**
 * The thread the websocket listener is running on. (not exposed out of this namespace)
 */
std::thread listener_thread;

/**
 * Used to pass down the default settings to the socket session
 */
sock::session_options sess_opts;

/**
 * Initializes the usr subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
int init()
{
    // Start listening for incoming user connections.
    start_listening();

    return 0;
}

/**
 * Free any resources used by usr subsystem (eg. socket listeners).
 */
void deinit()
{
    stop_listening();
}

/**
 * Adds the user denoted by specified session id and public key to the global authed user list.
 * This should get called after the challenge handshake is verified.
 * 
 * @param session User socket session.
 * @param pubkey User's binary public key.
 * @return 0 on successful additions. -1 on failure.
 */
int add_user(sock::socket_session<user_outbound_message> *session, const std::string &pubkey)
{
    const std::string &sessionid = session->uniqueid;
    if (users.count(sessionid) == 1)
    {
        LOG_INFO << sessionid << " already exist. Cannot add user.";
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(users_mutex);
        users.emplace(sessionid, usr::connected_user(session, pubkey));
    }

    // Populate sessionid map so we can lookup by user pubkey.
    sessionids.try_emplace(pubkey, sessionid);

    return 0;
}

/**
 * Removes the specified public key from the global user list.
 * This must get called when a user disconnects from HP.
 * 
 * @param sessionid User socket session id.
 * @return 0 on successful removals. -1 on failure.
 */
int remove_user(const std::string &sessionid)
{
    auto itr = users.find(sessionid);

    if (itr == users.end())
    {
        LOG_INFO << sessionid << " does not exist. Cannot remove user.";
        return -1;
    }

    usr::connected_user &user = itr->second;

    {
        std::lock_guard<std::mutex> lock(users_mutex);
        sessionids.erase(user.pubkey);
    }

    users.erase(itr);
    return 0;
}

/**
 * Starts listening for incoming user websocket connections.
 */
void start_listening()
{

    auto address = net::ip::make_address(conf::cfg.listenip);
    sess_opts.max_message_size = conf::cfg.pubmaxsize;
    sess_opts.max_bytes_per_minute = conf::cfg.pubmaxcpm;

    std::make_shared<sock::socket_server<user_outbound_message>>(
        ioc,
        ctx,
        tcp::endpoint{address, conf::cfg.pubport},
        global_usr_session_handler,
        sess_opts)
        ->run();

    listener_thread = std::thread([&] { ioc.run(); });

    LOG_INFO << "Started listening for incoming user connections...";
}

/**
 * Stops listening for incoming connections.
 */
void stop_listening()
{
    //TODO
}

} // namespace usr