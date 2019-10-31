#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <boost/thread/thread.hpp>
#include "usr.hpp"
#include "user_session_handler.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "../sock/socket_server.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"

namespace jusrmsg = jsonschema::usrmsg;

namespace usr
{

// Holds global connected-users and related objects.
connected_context ctx;

// Holds objects used by socket listener.
listener_context listener_ctx;

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

std::string issue_challenge(const std::string sessionid)
{
    std::string msgstr;
    std::string challengehex;
    jusrmsg::create_user_challenge(msgstr, challengehex);

    // Create an entry in pending_challenges for later tracking upon challenge response.
    ctx.pending_challenges.try_emplace(std::move(sessionid), challengehex);

    return msgstr;
}

bool verify_challenge(std::string_view message, sock::socket_session<user_outbound_message> *session)
{
    // The received message must be the challenge response. We need to verify it.
    auto itr = ctx.pending_challenges.find(session->uniqueid);
    if (itr == ctx.pending_challenges.end())
    {
        LOG_DBG << "No challenge found for the session " << session->uniqueid;
        return false;
    }

    std::string userpubkeyhex;
    std::string_view original_challenge = itr->second;
    if (jusrmsg::verify_user_challenge_response(userpubkeyhex, message, original_challenge) == 0)
    {
        // Challenge singature verification successful.

        // Decode hex pubkey and get binary pubkey. We are only going to keep
        // the binary pubkey due to reduced memory footprint.
        std::string userpubkey;
        userpubkey.resize(userpubkeyhex.length() / 2);
        util::hex2bin(
            reinterpret_cast<unsigned char *>(userpubkey.data()),
            userpubkey.length(),
            userpubkeyhex);

        // Now check whether this user public key is duplicate.
        if (ctx.sessionids.count(userpubkey) == 0)
        {
            // All good. Unique public key.
            // Promote the connection from pending-challenges to authenticated users.

            session->flags.reset(util::SESSION_FLAG::USER_CHALLENGE_ISSUED); // Clear challenge-issued flag
            session->flags.set(util::SESSION_FLAG::USER_AUTHED);             // Set the user-authed flag
            add_user(session, userpubkey);                                   // Add the user to the global authed user list
            ctx.pending_challenges.erase(session->uniqueid);                 // Remove the stored challenge

            LOG_INFO << "User connection " << session->uniqueid << " authenticated. Public key "
                     << userpubkeyhex;
            return true;
        }
        else
        {
            LOG_INFO << "Duplicate user public key " << session->uniqueid;
        }
    }
    else
    {
        LOG_INFO << "Challenge verification failed " << session->uniqueid;
    }

    return false;
}

void handle_user_message(connected_user &user, std::string_view message)
{
    {
        std::lock_guard<std::mutex> lock(ctx.users_mutex);
        //Add to the hashed input buffer list.
        user.inputs.push_back(util::hash_buffer(message, user.pubkey));
    }

    LOG_DBG << "Collected " << message.length() << " bytes from user";
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
    if (ctx.users.count(sessionid) == 1)
    {
        LOG_INFO << sessionid << " already exist. Cannot add user.";
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(ctx.users_mutex);
        ctx.users.emplace(sessionid, usr::connected_user(session, pubkey));
    }

    // Populate sessionid map so we can lookup by user pubkey.
    ctx.sessionids.try_emplace(pubkey, sessionid);

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
    auto itr = ctx.users.find(sessionid);

    if (itr == ctx.users.end())
    {
        LOG_INFO << sessionid << " does not exist. Cannot remove user.";
        return -1;
    }

    usr::connected_user &user = itr->second;

    {
        std::lock_guard<std::mutex> lock(ctx.users_mutex);
        ctx.sessionids.erase(user.pubkey);
    }

    ctx.users.erase(itr);
    return 0;
}

/**
 * Starts listening for incoming user websocket connections.
 */
void start_listening()
{

    auto address = net::ip::make_address(conf::cfg.listenip);
    listener_ctx.sess_opts.max_message_size = conf::cfg.pubmaxsize;
    listener_ctx.sess_opts.max_bytes_per_minute = conf::cfg.pubmaxcpm;

    std::make_shared<sock::socket_server<user_outbound_message>>(
        listener_ctx.ioc,
        listener_ctx.ssl_ctx,
        tcp::endpoint{address, conf::cfg.pubport},
        listener_ctx.global_usr_session_handler,
        listener_ctx.sess_opts)
        ->run();

    listener_ctx.listener_thread = std::thread([&] { listener_ctx.ioc.run(); });

    LOG_INFO << "Started listening for incoming user connections...";
}

} // namespace usr