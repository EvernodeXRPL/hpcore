#include "../pchheader.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "../sock/socket_server.hpp"
#include "../sock/socket_session.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"
#include "user_input.hpp"

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

/**
 * Verifies the given message for a previously issued user challenge.
 * @param message Challenge response.
 * @param session The socket session that received the response.
 * @return 0 for successful verification. -1 for failure.
 */
int verify_challenge(std::string_view message, sock::socket_session<user_outbound_message> *session)
{
    // The received message must be the challenge response. We need to verify it.
    auto itr = ctx.pending_challenges.find(session->uniqueid);
    if (itr == ctx.pending_challenges.end())
    {
        LOG_DBG << "No challenge found for the session " << session->uniqueid;
        return -1;
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

            session->flags.reset(sock::SESSION_FLAG::USER_CHALLENGE_ISSUED); // Clear challenge-issued flag
            session->flags.set(sock::SESSION_FLAG::USER_AUTHED);             // Set the user-authed flag
            add_user(session, userpubkey);                                   // Add the user to the global authed user list
            ctx.pending_challenges.erase(session->uniqueid);                 // Remove the stored challenge

            LOG_INFO << "User connection " << session->uniqueid << " authenticated. Public key "
                     << userpubkeyhex;
            return 0;
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

    return -1;
}

/**
 * Processes a message sent by a connected user. This will be invoked by web socket on_message handler.
 * @param user The authenticated user who sent the message.
 * @param message The message sent by user.
 * @return 0 on successful processing. -1 for failure.
 */
int handle_user_message(connected_user &user, std::string_view message)
{
    rapidjson::Document d;
    if (jusrmsg::parse_user_message(d, message) == 0)
    {
        // Message is a contract input message.
        if (d[jusrmsg::FLD_TYPE] == jusrmsg::MSGTYPE_CONTRACT_INPUT)
        {
            std::string contentjson;
            std::string sig;
            if (jusrmsg::extract_signed_input_container(contentjson, sig, d) == 0)
            {
                std::lock_guard<std::mutex> lock(ctx.users_mutex);
                
                //Add to the submitted input list.
                user.submitted_inputs.push_back(user_submitted_message(
                    std::move(contentjson),
                    std::move(sig)));
                return 0;
            }
        }
        else
        {
            LOG_DBG << "Invalid user message type: " << d[jusrmsg::FLD_TYPE].GetString();
        }
    }

    // Bad message.
    return -1;
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
    listener_ctx.sess_opts.max_socket_read_len = conf::cfg.pubmaxsize;
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