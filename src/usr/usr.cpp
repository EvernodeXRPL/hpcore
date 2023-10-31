#include "../pchheader.hpp"
#include "../msg/json/usrmsg_json.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "../msg/usrmsg_common.hpp"
#include "../util/util.hpp"
#include "../util/sequence_hash.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"
#include "../ledger/ledger.hpp"
#include "../util/buffer_store.hpp"
#include "../hpfs/hpfs_mount.hpp"
#include "../status.hpp"
#include "usr.hpp"
#include "user_comm_session.hpp"
#include "user_comm_server.hpp"
#include "user_input.hpp"
#include "read_req.hpp"
#include "input_nonce_map.hpp"
#include "../hpsh/hpsh.hpp"

namespace usr
{

    // Holds global connected-users and related objects.
    connected_context ctx;

    util::buffer_store input_store;
    input_nonce_map nonce_map;
    uint64_t metric_thresholds[5];
    bool init_success = false;

    /**
     * Initializes the usr subsystem. Must be called once during application startup.
     * @return 0 for successful initialization. -1 for failure.
     */
    int init()
    {
        metric_thresholds[0] = conf::cfg.user.max_bytes_per_min;
        metric_thresholds[1] = 0; // This metric doesn't apply to user context.
        metric_thresholds[2] = 0; // This metric doesn't apply to user context.
        metric_thresholds[3] = conf::cfg.user.max_bad_msgs_per_min;
        metric_thresholds[4] = conf::cfg.user.idle_timeout;

        if (input_store.init() == -1)
            return -1;

        // Start listening for incoming user connections only if user connection listening is enabled.
        if (conf::cfg.user.listen)
        {
            if (start_listening() == -1)
                return -1;
        }
        else
        {
            LOG_INFO << "User connection listner isn't started since user connections are disabled.";
        }

        init_success = true;
        return 0;
    }

    /**
     * Cleanup any running processes.
     */
    void deinit()
    {
        if (init_success)
        {
            // Stop com server only if user connections config is enabled (Otherwise server hasn't been started).
            if (conf::cfg.user.listen)
                ctx.server->stop();

            input_store.deinit();
        }
    }

    /**
     * Starts listening for incoming user websocket connections.
     */
    int start_listening()
    {
        ctx.server.emplace("User", conf::cfg.user.port, metric_thresholds, conf::cfg.user.max_bytes_per_msg,
                           conf::cfg.user.max_connections, conf::cfg.user.max_in_connections_per_host, false, false);
        if (ctx.server->start() == -1)
            return -1;

        LOG_INFO << "Started listening for user connections on " << std::to_string(conf::cfg.user.port);
        return 0;
    }

    /**
     * Verifies the given message for a previously issued user challenge.
     * @param message Challenge response.
     * @param session The socket session that received the response.
     * @return 0 for successful verification. -1 for failure.
     */
    int verify_challenge(std::string_view message, usr::user_comm_session &session)
    {
        // The received message must be the challenge response. We need to verify it.
        if (session.issued_challenge.empty())
        {
            LOG_DEBUG << "No user challenge found for the session " << session.display_name();
            return -1;
        }

        std::string user_pubkey_hex;
        std::string protocol_code;
        std::string server_challenge;
        if (msg::usrmsg::json::verify_user_challenge(user_pubkey_hex, protocol_code, server_challenge, message, session.issued_challenge) == 0)
        {
            // If user has specified server challange, we need to send a challenge response.
            if (!server_challenge.empty())
            {
                std::vector<uint8_t> msg;
                msg::usrmsg::json::create_server_challenge_response(msg, server_challenge);
                session.send(msg);
            }

            // Challenge signature verification successful. Add the user to our global user list.
            add_user(session, user_pubkey_hex, protocol_code);
            return 0;
        }
        else
        {
            LOG_DEBUG << "User challenge verification failed " << session.display_name();
            return -1;
        }
    }

    /**
     * Processes a message sent by a authenticated user. This will be invoked by web socket on_message handler.
     * @param user The authenticated user who sent the message.
     * @param message The message sent by user.
     * @return 0 on successful processing. -1 for failure.
     */
    int handle_authed_user_message(connected_user &user, std::string_view message)
    {
        msg::usrmsg::usrmsg_parser parser(user.protocol);

        if (parser.parse(message) == 0)
        {
            std::string msg_type;
            parser.extract_type(msg_type);

            if (msg_type == msg::usrmsg::MSGTYPE_CONTRACT_READ_REQUEST)
            {
                // Ignore the request if contract execution is disabled or read requests disallowed.
                if (!conf::cfg.contract.execute || conf::cfg.user.concurrent_read_requests == 0)
                    return 0;

                std::string id, content;
                if (parser.extract_read_request(id, content) != -1)
                {
                    if (read_req::populate_read_req_queue(user.pubkey, std::move(id), std::move(content)) == -1)
                    {
                        LOG_WARNING << "Failed to enqueue read request.";
                    }
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

                std::string input_container;
                std::string sig;
                if (parser.extract_signed_input_container(input_container, sig) != -1)
                {
                    std::scoped_lock<std::mutex> lock(ctx.users_mutex);

                    std::string input_data;
                    uint64_t nonce;
                    uint64_t max_ledger_seq_no;
                    if (parser.extract_input_container(input_data, nonce, max_ledger_seq_no, input_container) != -1)
                    {
                        const util::sequence_hash lcl_id = ledger::ctx.get_lcl_id();
                        // Ignore the input if the max ledger seq number specified is beyond the max offeset.
                        if (conf::cfg.contract.max_input_ledger_offset != 0 && max_ledger_seq_no > lcl_id.seq_no + conf::cfg.contract.max_input_ledger_offset)
                        {
                            send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_MAX_LEDGER_OFFSET_EXCEEDED, crypto::get_hash(sig));
                            return -1;
                        }

                        // Ignore the input if our ledger has passed the input TTL.
                        if (max_ledger_seq_no <= lcl_id.seq_no)
                        {
                            send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_MAX_LEDGER_EXPIRED, crypto::get_hash(sig));
                            return -1;
                        }

                        // Check whether the newly received input is going to cause overflow of round input limit.
                        if (conf::cfg.contract.round_limits.user_input_bytes > 0 &&
                            (user.collected_input_size + input_data.size()) > conf::cfg.contract.round_limits.user_input_bytes)
                        {
                            send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_ROUND_INPUTS_OVERFLOW, crypto::get_hash(sig));
                            return -1;
                        }

                        const int nonce_status = nonce_map.check(user.pubkey, nonce, sig, max_ledger_seq_no, true);
                        if (nonce_status == 0)
                        {
                            // Add to the submitted input list.
                            user.submitted_inputs.push_back(submitted_user_input{
                                std::move(input_container),
                                std::move(sig),
                                user.protocol});

                            // Increment the collected input size counter. This will be reset whenever collected inputs are moved
                            // to concensus candidate input set.
                            user.collected_input_size += input_data.size();
                            return 0;
                        }
                        else
                        {
                            const char *reason = nonce_status == 1 ? msg::usrmsg::REASON_NONCE_EXPIRED : msg::usrmsg::REASON_ALREADY_SUBMITTED;
                            send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, reason, crypto::get_hash(sig));
                            return -1;
                        }
                    }
                    else
                    {
                        send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, crypto::get_hash(sig));
                        return -1;
                    }
                }
                else
                {
                    send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, crypto::get_hash(sig));
                    return -1;
                }
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_STAT)
            {
                std::vector<uint8_t> resp;
                parser.create_status_response(resp);
                user.session.send(resp);
                return 0;
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_LCL)
            {
                std::vector<uint8_t> resp;
                parser.create_lcl_response(resp);
                user.session.send(resp);
                return 0;
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_SUBSCRIPTION)
            {
                NOTIFICATION_CHANNEL channel;
                bool enabled;
                if (parser.extract_subscription_request(channel, enabled) == -1)
                    return -1;

                user.subscriptions[channel] = enabled;
                return 0;
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_LEDGER_QUERY)
            {
                ledger::query::query_request req;
                std::string id;
                if (parser.extract_ledger_query(req, id) == -1)
                    return -1;

                const ledger::query::query_result result = ledger::query::execute(user.pubkey, req);

                std::vector<uint8_t> resp;
                parser.create_ledger_query_response(resp, id, result);
                user.session.send(resp);
                return 0;
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_HPSH_REQUEST)
            {
                std::string id, content;
                if (hpsh::ctx.is_initialized && parser.extract_hpsh_request(id, content) != -1)
                {
                    if (hpsh::execute(id, user.pubkey, content.c_str()) == -1)
                        return -1;

                    return 0;
                }
                else
                {
                    send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, "");
                    return -1;
                }
            }
            else
            {
                LOG_DEBUG << "Invalid user message type: " << msg_type;
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
     * Sends multiple user input responses grouped by user.
     * @param responses The collection of status responses to be sent out.
     * @param ledger_seq_no The ledger seq no to indicate in accepted responses. Ignored for 'rejected' responses or for
     *                      individual responses having their own ledger information.
     * @param ledger_hash The ledger hash to indicate in accepted responses. Ignored for 'rejected' responses or for
     *                      individual responses having their own ledger information.
     */
    void send_input_status_responses(const std::unordered_map<std::string, std::vector<input_status_response>> &responses,
                                     const uint64_t ledger_seq_no, const util::h32 &ledger_hash)
    {
        if (responses.empty())
            return;

        // Lock the user sessions.
        std::scoped_lock lock(usr::ctx.users_mutex);

        for (auto &[pubkey, user_responses] : responses)
        {
            // Locate this user's socket session.
            const auto user_itr = usr::ctx.users.find(pubkey);
            if (user_itr != usr::ctx.users.end())
            {
                msg::usrmsg::usrmsg_parser parser(user_itr->second.protocol);

                // Send the request status result if this user is connected to us.
                for (const input_status_response &resp : user_responses)
                {
                    // We are not sending any status response for 'already submitted' inputs. This is because the user
                    // would have gotten the proper status response during first submission.
                    if (resp.reject_reason != msg::usrmsg::REASON_ALREADY_SUBMITTED)
                    {
                        send_input_status(parser,
                                          user_itr->second.session,
                                          resp.reject_reason == NULL ? msg::usrmsg::STATUS_ACCEPTED : msg::usrmsg::STATUS_REJECTED,
                                          resp.reject_reason == NULL ? "" : resp.reject_reason,
                                          resp.input_hash,
                                          // Give priority ledger seq no/hash contained in individual responses.
                                          resp.ledger_seq_no == 0 ? ledger_seq_no : resp.ledger_seq_no,
                                          resp.ledger_hash == util::h32_empty ? ledger_hash : resp.ledger_hash);
                    }
                }
            }
        }
    }

    /**
     * Send the specified contract input status result via the provided session.
     */
    void send_input_status(const msg::usrmsg::usrmsg_parser &parser, usr::user_comm_session &session,
                           std::string_view status, std::string_view reason, std::string_view input_hash,
                           const uint64_t ledger_seq_no, const util::h32 &ledger_hash)
    {
        std::vector<uint8_t> msg;
        parser.create_contract_input_status(msg, status, reason, input_hash, ledger_seq_no, ledger_hash);
        session.send(msg);
    }

    /**
     * Adds the user denoted by specified session id and public key to the global authed user list.
     * This should get called after the challenge handshake is verified.
     *
     * @param session User socket session.
     * @param user_pubkey_hex User's hex public key.
     * @param protocol_code Messaging protocol used by user.
     * @return 0 on successful additions. -1 on failure.
     */
    int add_user(usr::user_comm_session &session, const std::string &pubkey_hex, std::string_view protocol_code)
    {
        // If max number of user connections reached skip the rest.
        if (ctx.users.size() == MAX_USER_COUNT)
        {
            LOG_DEBUG << "Rejecting " + session.display_name() << ". Maximum user count reached.";
            return -1;
        }

        // Decode hex pubkey and get binary pubkey.
        const std::string pubkey = util::to_bin(pubkey_hex);

        // Acquire user list lock.
        std::scoped_lock<std::mutex> lock(ctx.users_mutex);

        // Now check whether this user public key is a duplicate.
        if (ctx.users.count(pubkey) == 0)
        {
            // All good. Unique public key.
            // Promote the connection from pending-challenges to authenticated users.

            const util::PROTOCOL protocol = (protocol_code == "json" ? util::PROTOCOL::JSON : util::PROTOCOL::BSON);

            session.mark_as_verified();       // Mark connection as a verified connection.
            session.issued_challenge.clear(); // Remove the stored challenge
            session.uniqueid = pubkey_hex;
            session.pubkey = pubkey;

            // Add the user to the global authed user list
            ctx.users.emplace(pubkey, usr::connected_user(session, pubkey, protocol));
            LOG_DEBUG << "User connection authenticated. Public key " << pubkey_hex;
        }
        else
        {
            LOG_DEBUG << "Duplicate user public key " << session.display_name();
        }

        return 0;
    }

    /**
     * Removes the specified public key from the global user list.
     * This must get called when an authenticated user disconnects from HP.
     *
     * @param pubkey User pubkey.
     * @return 0 on successful removals. -1 on failure.
     */
    int remove_user(const std::string &pubkey)
    {
        std::scoped_lock<std::mutex> lock(ctx.users_mutex);
        ctx.users.erase(pubkey);
        return 0;
    }

    const char *extract_submitted_input(const std::string &user_pubkey, const usr::submitted_user_input &submitted, usr::extracted_user_input &extracted)
    {
        // Verify the signature of the submitted input_container.
        if (crypto::verify(submitted.input_container, submitted.sig, user_pubkey) == -1)
        {
            LOG_DEBUG << "User input bad signature.";
            return msg::usrmsg::REASON_BAD_SIG;
        }

        // Extract information from input container.
        msg::usrmsg::usrmsg_parser parser(submitted.protocol);
        if (parser.extract_input_container(extracted.input, extracted.nonce, extracted.max_ledger_seq_no, submitted.input_container) == -1)
        {
            LOG_DEBUG << "User input bad input container format.";
            return msg::usrmsg::REASON_BAD_MSG_FORMAT;
        }

        extracted.sig = std::move(submitted.sig);

        return NULL;
    }

    /**
     * Validates the provided user input message against all the required criteria.
     * @return The rejection reason if input rejected. NULL if the input can be accepted.
     */
    const char *validate_user_input_submission(const std::string &user_pubkey, const usr::extracted_user_input &extracted_input,
                                               const uint64_t lcl_seq_no, size_t &total_input_size, std::string &ordered_hash, util::buffer_view &input)
    {
        // Ordered hash is used as the globally unqiue 'key' to represent this input for this consensus round.
        // It is prefixed with the nonce to support user-defined sort order and the input hash is appended
        // to make it unique among inputs from all users.
        // Ordered hash = nonce (8 bytes) + input hash (32 bytes)
        // In the ledger, we will store the nonce and input hash separately.
        ordered_hash = util::uint64_to_string_bytes(extracted_input.nonce) + crypto::get_hash(extracted_input.sig);

        // Ignore the input if the max ledger seq number specified is beyond the max offeset.
        if (conf::cfg.contract.max_input_ledger_offset != 0 && extracted_input.max_ledger_seq_no > lcl_seq_no + conf::cfg.contract.max_input_ledger_offset)
        {
            LOG_DEBUG << "User input bad max ledger seq beyond the max offset.";
            return msg::usrmsg::REASON_MAX_LEDGER_OFFSET_EXCEEDED;
        }

        // Ignore the input if our ledger has passed the input TTL.
        if (extracted_input.max_ledger_seq_no <= lcl_seq_no)
        {
            LOG_DEBUG << "User input bad max ledger seq expired.";
            return msg::usrmsg::REASON_MAX_LEDGER_EXPIRED;
        }

        // Check subtotal of inputs extracted so far with the input size limit.
        const size_t new_total_input_size = total_input_size + extracted_input.input.size();
        if (conf::cfg.contract.round_limits.user_input_bytes > 0 &&
            new_total_input_size > conf::cfg.contract.round_limits.user_input_bytes)
        {
            LOG_DEBUG << "User input input exceeds round limit.";
            return msg::usrmsg::REASON_ROUND_INPUTS_OVERFLOW;
        }

        const int nonce_status = nonce_map.check(user_pubkey, extracted_input.nonce, extracted_input.sig, extracted_input.max_ledger_seq_no);
        if (nonce_status > 0)
        {
            LOG_DEBUG << (nonce_status == 1 ? "User input nonce expired." : "User input with same nonce/sig already submitted.");
            return (nonce_status == 1 ? msg::usrmsg::REASON_NONCE_EXPIRED : msg::usrmsg::REASON_ALREADY_SUBMITTED);
        }

        // Reaching here means the input is successfully validated and we can submit it to consensus.

        // Copy the input data into the input store. Contract will read the input from this location.
        input = input_store.write_buf(extracted_input.input.data(), extracted_input.input.size());

        // Increment the total valid input size so far.
        total_input_size = new_total_input_size;

        return NULL; // Success. No reject reason.
    }

    /**
     * Sends any change event notifications to relevant users who are currently connected to the node.
     */
    void dispatch_change_events()
    {
        status::change_event ev;
        while (status::event_queue.try_dequeue(ev))
        {
            // Array to hold constructed message cache from each protocol.
            std::vector<uint8_t> protocol_msgs[2];

            if (ev.index() == 0) // UNL change event. Broadcast for subscribed users.
            {
                std::scoped_lock<std::mutex> lock(ctx.users_mutex);
                for (auto &[sid, user] : ctx.users)
                {
                    if (user.subscriptions[NOTIFICATION_CHANNEL::UNL_CHANGE])
                    {
                        std::vector<uint8_t> &msg = protocol_msgs[user.protocol];
                        if (msg.empty()) // Construct the message with relevant protocol if not done so already.
                        {
                            msg::usrmsg::usrmsg_parser parser(user.protocol);
                            const status::unl_change_event &unl_ev = std::get<status::unl_change_event>(ev);
                            parser.create_unl_notification(msg, unl_ev.unl);
                        }
                        user.session.send(msg);
                    }
                }
            }
            else if (ev.index() == 1 || ev.index() == 2) // Ledger events. Broadcast for subscribed users.
            {
                std::scoped_lock<std::mutex> lock(ctx.users_mutex);
                for (auto &[sid, user] : ctx.users)
                {
                    if (user.subscriptions[NOTIFICATION_CHANNEL::LEDGER_EVENT])
                    {
                        std::vector<uint8_t> &msg = protocol_msgs[user.protocol];
                        if (msg.empty()) // Construct the message with relevant protocol if not done so already.
                        {
                            msg::usrmsg::usrmsg_parser parser(user.protocol);

                            if (ev.index() == 1) // Ledger created event.
                            {
                                const status::ledger_created_event &ledger_ev = std::get<status::ledger_created_event>(ev);
                                parser.create_ledger_created_notification(msg, ledger_ev.ledger);
                            }
                            else if (ev.index() == 2) // Vote status chnge event.
                            {
                                const status::vote_status_change_event &vote_ev = std::get<status::vote_status_change_event>(ev);
                                parser.create_vote_status_notification(msg, vote_ev.vote_status);
                            }
                        }
                        user.session.send(msg);
                    }
                }
            }
            else if (ev.index() == 3) // Health events. Broadcast for subscribed users.
            {
                std::scoped_lock<std::mutex> lock(ctx.users_mutex);
                for (auto &[sid, user] : ctx.users)
                {
                    if (user.subscriptions[NOTIFICATION_CHANNEL::HEALTH_STAT])
                    {
                        std::vector<uint8_t> &msg = protocol_msgs[user.protocol];
                        if (msg.empty()) // Construct the message with relevant protocol if not done so already.
                        {
                            msg::usrmsg::usrmsg_parser parser(user.protocol);
                            const status::health_event &health_ev = std::get<status::health_event>(ev);
                            parser.create_health_notification(msg, health_ev);
                        }
                        user.session.send(msg);
                    }
                }
            }
        }
    }

} // namespace usr