#include "../pchheader.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "../msg/usrmsg_common.hpp"
#include "../comm/comm_server.hpp"
#include "../comm/comm_session.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"
#include "user_input.hpp"

namespace usr
{

    // Holds global connected-users and related objects.
    connected_context ctx;

    uint64_t metric_thresholds[4];
    bool init_success = false;

    /**
 * Initializes the usr subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
    int init()
    {
        metric_thresholds[0] = conf::cfg.pubmaxcpm;
        metric_thresholds[1] = 0;
        metric_thresholds[2] = 0;
        metric_thresholds[3] = conf::cfg.pubmaxbadmpm;

        // Start listening for incoming user connections.
        if (start_listening() == -1)
            return -1;

        init_success = true;
        return 0;
    }

    /**
 * Cleanup any running processes.
 */
    void deinit()
    {
        if (init_success)
            ctx.listener.stop();
    }

    /**
 * Starts listening for incoming user websocket connections.
 */
    int start_listening()
    {
        if (ctx.listener.start(
                conf::cfg.pubport, ".sock-user", comm::SESSION_TYPE::USER, true, true, metric_thresholds, std::set<conf::ip_port_pair>(), conf::cfg.pubmaxsize) == -1)
            return -1;

        LOG_INFO << "Started listening for user connections on " << std::to_string(conf::cfg.pubport);
        return 0;
    }

    /**
 * Verifies the given message for a previously issued user challenge.
 * @param message Challenge response.
 * @param session The socket session that received the response.
 * @return 0 for successful verification. -1 for failure.
 */
    int verify_challenge(std::string_view message, comm::comm_session &session)
    {
        // The received message must be the challenge response. We need to verify it.
        if (session.issued_challenge.empty())
        {
            LOG_DBG << "No challenge found for the session " << session.uniqueid;
            return -1;
        }

        std::string userpubkeyhex;
        std::string protocol_code;
        std::string_view original_challenge = session.issued_challenge;

        msg::usrmsg::usrmsg_parser parser(util::PROTOCOL::JSON);
        if (parser.verify_user_handshake_response(userpubkeyhex, protocol_code, message, original_challenge) == 0)
        {
            // Challenge signature verification successful.

            // Decode hex pubkey and get binary pubkey. We are only going to keep
            // the binary pubkey due to reduced memory footprint.
            std::string userpubkey;
            userpubkey.resize(userpubkeyhex.length() / 2);
            util::hex2bin(
                reinterpret_cast<unsigned char *>(userpubkey.data()),
                userpubkey.length(),
                userpubkeyhex);

            // Now check whether this user public key is a duplicate.
            if (ctx.sessionids.count(userpubkey) == 0)
            {
                // All good. Unique public key.
                // Promote the connection from pending-challenges to authenticated users.

                const util::PROTOCOL user_protocol = (protocol_code == "json" ? util::PROTOCOL::JSON : util::PROTOCOL::BSON);

                session.challenge_status = comm::CHALLENGE_VERIFIED; // Set as challenge verified
                add_user(session, userpubkey, user_protocol);        // Add the user to the global authed user list
                session.issued_challenge.clear();                    // Remove the stored challenge

                LOG_DBG << "User connection " << session.uniqueid << " authenticated. Public key "
                        << userpubkeyhex;
                return 0;
            }
            else
            {
                LOG_DBG << "Duplicate user public key " << session.uniqueid;
            }
        }
        else
        {
            LOG_DBG << "Challenge verification failed " << session.uniqueid;
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
        msg::usrmsg::usrmsg_parser parser(user.protocol);

        if (parser.parse(message) == 0)
        {
            std::string msg_type;
            parser.extract_type(msg_type);

            if (msg_type == msg::usrmsg::MSGTYPE_CONTRACT_READ_REQUEST)
            {
                std::string content;
                if (parser.extract_read_request(content) == 0)
                {
                    std::lock_guard<std::mutex> lock(ctx.users_mutex);

                    //Add to the user's pending read requests list.
                    user.read_requests.push_back(std::move(content));
                    return 0;
                }
                else
                {
                    send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, "");
                    return -1;
                }
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_CONTRACT_INPUT)
            {
                // Message is a contract input message.

                std::string input_container_json;
                std::string sig;
                if (parser.extract_signed_input_container(input_container_json, sig) == 0)
                {
                    std::lock_guard<std::mutex> lock(ctx.users_mutex);

                    //Add to the submitted input list.
                    user.submitted_inputs.push_back(user_input(
                        std::move(input_container_json),
                        std::move(sig)));
                    return 0;
                }
                else
                {
                    send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_SIG, sig);
                    return -1;
                }
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_STAT)
            {
                std::string msg;
                parser.create_status_response(msg);
                user.session.send(msg);
                return 0;
            }
            else
            {
                LOG_DBG << "Invalid user message type: " << msg_type;
                send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_INVALID_MSG_TYPE, "");
                return -1;
            }
        }
        else
        {
            // Bad message.
            send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, "");
            return -1;
        }
    }

    /**
 * Send the specified contract input status result via the provided session.
 */
    void send_input_status(const msg::usrmsg::usrmsg_parser &parser, const comm::comm_session &session,
                           std::string_view status, std::string_view reason, std::string_view input_sig)
    {
        std::string msg;
        parser.create_contract_input_status(msg, status, reason, input_sig);
        session.send(msg);
    }

    /**
 * Adds the user denoted by specified session id and public key to the global authed user list.
 * This should get called after the challenge handshake is verified.
 * 
 * @param session User socket session.
 * @param pubkey User's binary public key.
 * @param protocol Messaging protocol used by user.
 * @return 0 on successful additions. -1 on failure.
 */
    int add_user(const comm::comm_session &session, const std::string &pubkey, const util::PROTOCOL protocol)
    {
        const std::string &sessionid = session.uniqueid;
        if (ctx.users.count(sessionid) == 1)
        {
            LOG_INFO << sessionid << " already exist. Cannot add user.";
            return -1;
        }

        {
            std::lock_guard<std::mutex> lock(ctx.users_mutex);
            ctx.users.emplace(sessionid, usr::connected_user(session, pubkey, protocol));
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
        const auto itr = ctx.users.find(sessionid);

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
 * Finds and returns the socket session for the proided user pubkey.
 * @param pubkey User binary pubkey.
 * @return Pointer to the socket session. NULL of not found.
 */
    const comm::comm_session *get_session_by_pubkey(const std::string &pubkey)
    {
        const auto sessionid_itr = ctx.sessionids.find(pubkey);
        if (sessionid_itr != ctx.sessionids.end())
        {
            const auto user_itr = ctx.users.find(sessionid_itr->second);
            if (user_itr != ctx.users.end())
                return &user_itr->second.session;
        }

        return NULL;
    }

} // namespace usr