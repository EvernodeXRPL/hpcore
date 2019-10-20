#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <rapidjson/document.h>
#include <sodium.h>
#include <boost/thread/thread.hpp>
#include "../sock/socket_server.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"

namespace usr
{

/**
 * Connected (authenticated) user list. (Exposed to other sub systems)
 * Map key: User socket session id (<ip:port>)
 */
std::unordered_map<std::string, usr::connected_user> users;

/**
 * Holds set of connected user session ids and public keys for lookups.
 * This is used for pubkey duplicate checks as well.
 * Map key: User binary pubkey
 */
std::unordered_map<std::string, std::string> sessionids;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 * Map key: User socket session id (<ip:port>)
 */
std::unordered_map<std::string, std::string> pending_challenges;

/**
 * User session handler instance. This instance's methods will be fired for any user socket activity.
 */
usr::user_session_handler global_usr_session_handler;

/**
 * The IO context used by the websocket listener. (not exposed out of this namespace)
 */
net::io_context ioc;

/**
 * The thread the websocket lsitener is running on. (not exposed out of this namespace)
 */
std::thread listener_thread;

// Challenge response fields.
// These fields are used on challenge response validation.
static const char *CHALLENGE_RESP_TYPE = "type";
static const char *CHALLENGE_RESP_CHALLENGE = "challenge";
static const char *CHALLENGE_RESP_SIG = "sig";
static const char *CHALLENGE_RESP_PUBKEY = "pubkey";

// Message type for the user challenge.
static const char *CHALLENGE_MSGTYPE = "public_challenge";
// Message type for the user challenge response.
static const char *CHALLENGE_RESP_MSGTYPE = "challenge_response";
// Length of user random challenge bytes.
static const size_t CHALLENGE_LEN = 16;

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
 * Constructs user challenge message json and the challenge string required for
 * initial user challenge handshake. This gets called when a user gets establishes
 * a web sockets connection to HP.
 * 
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "version": "<HP version>",
 *              "type": "public_challenge",
 *              "challenge": "<hex challenge string>"
 *            }
 * @param challenge String reference to copy the generated hex challenge string into.
 */
void create_user_challenge(std::string &msg, std::string &challengehex)
{
    //Use libsodium to generate the random challenge bytes.
    unsigned char challenge_bytes[CHALLENGE_LEN];
    randombytes_buf(challenge_bytes, CHALLENGE_LEN);

    //We pass the hex challenge string separately to the caller even though
    //we also include it in the challenge msg as well.

    util::bin2hex(challengehex, challenge_bytes, CHALLENGE_LEN);

    //Construct the challenge msg json.
    // We do not use RapidJson here in favour of performance because this is a simple json message.

    // Since we know the rough size of the challenge massage we reserve adequate amount for the holder.
    // Only Hot Pocket version number is variable length. Therefore message size is roughly 95 bytes
    // so allocating 128bits for heap padding.
    msg.reserve(128);
    msg.append("{\"version\":\"")
        .append(util::HP_VERSION)
        .append("\",\"type\":\"public_challenge\",\"challenge\":\"")
        .append(challengehex)
        .append("\"}");
}

/**
 * Verifies the user challenge response with the original challenge issued to the user
 * and the user public key contained in the response.
 * 
 * @param extracted_pubkeyhex The hex public key extracted from the response. 
 * @param response The response bytes to verify. This will be parsed as json.
 *                 Accepted response format:
 *                 {
 *                   "type": "challenge_response",
 *                   "challenge": "<original hex challenge the user received>",
 *                   "sig": "<hex signature of the challenge>",
 *                   "pubkey": "<hex public key of the user>"
 *                 }
 * @param original_challenge The original hex challenge string issued to the user.
 * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
 */
int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge)
{
    // We load response raw bytes into json document.
    rapidjson::Document d;
    d.Parse(response.data());
    if (d.HasParseError())
    {
        LOG_INFO << "Challenge response json parsing failed.";
        return -1;
    }

    // Validate msg type.
    if (!d.HasMember(CHALLENGE_RESP_TYPE) || d[CHALLENGE_RESP_TYPE] != CHALLENGE_RESP_MSGTYPE)
    {
        LOG_INFO << "User challenge response type invalid. 'challenge_response' expected.";
        return -1;
    }

    // Compare the response challenge string with the original issued challenge.
    if (!d.HasMember(CHALLENGE_RESP_CHALLENGE) || d[CHALLENGE_RESP_CHALLENGE] != original_challenge.data())
    {
        LOG_INFO << "User challenge response challenge invalid.";
        return -1;
    }

    // Check for the 'sig' field existence.
    if (!d.HasMember(CHALLENGE_RESP_SIG) || !d[CHALLENGE_RESP_SIG].IsString())
    {
        LOG_INFO << "User challenge response signature invalid.";
        return -1;
    }

    // Check for the 'pubkey' field existence.
    if (!d.HasMember(CHALLENGE_RESP_PUBKEY) || !d[CHALLENGE_RESP_PUBKEY].IsString())
    {
        LOG_INFO << "User challenge response public key invalid.";
        return -1;
    }

    // Verify the challenge signature. We do this last due to signature verification cost.
    std::string_view pubkeysv = util::getsv(d[CHALLENGE_RESP_PUBKEY]);
    if (crypto::verify_hex(
            original_challenge,
            util::getsv(d[CHALLENGE_RESP_SIG]),
            pubkeysv) != 0)
    {
        LOG_INFO << "User challenge response signature verification failed.";
        return -1;
    }

    extracted_pubkeyhex = pubkeysv;

    return 0;
}

/**
 * Adds the user denoted by specified session id and public key to the global authed user list.
 * This should get called after the challenge handshake is verified.
 * 
 * @param session User socket session.
 * @param pubkey User's binary public key.
 * @return 0 on successful additions. -1 on failure.
 */
int add_user(sock::socket_session *session, const std::string &pubkey)
{
    const std::string &sessionid = session->uniqueid_;
    if (users.count(sessionid) == 1)
    {
        LOG_INFO << sessionid << " already exist. Cannot add user.";
        return -1;
    }

    users.emplace(sessionid, usr::connected_user(session, pubkey));

    // Populate sessionid map so we can lookup by user pubkey.
    sessionids[pubkey] = sessionid;

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

    sessionids.erase(user.pubkey);
    users.erase(itr);
    return 0;
}

/**
 * Starts listening for incoming user websocket connections.
 */
void start_listening()
{
    auto address = net::ip::make_address(conf::cfg.listenip);
    std::make_shared<sock::socket_server>(
        ioc,
        tcp::endpoint{address, conf::cfg.pubport},
        global_usr_session_handler)
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