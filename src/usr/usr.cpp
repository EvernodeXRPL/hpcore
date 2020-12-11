#include "../pchheader.hpp"
#include "../msg/json/usrmsg_json.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "../msg/usrmsg_common.hpp"
#include "../util/util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"
#include "../ledger.hpp"
#include "../util/buffer_store.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"
#include "user_comm_session.hpp"
#include "user_comm_server.hpp"
#include "user_input.hpp"
#include "read_req.hpp"
#include "input_nonce_map.hpp"

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
        metric_thresholds[0] = conf::cfg.pubmaxcpm;
        metric_thresholds[1] = 0; // This metric doesn't apply to user context.
        metric_thresholds[2] = 0; // This metric doesn't apply to user context.
        metric_thresholds[3] = conf::cfg.pubmaxbadmpm;
        metric_thresholds[4] = conf::cfg.pubidletimeout;

        if (input_store.init() == -1)
            return -1;

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
        {
            ctx.server->stop();
            input_store.deinit();
        }
    }

    /**
     * Starts listening for incoming user websocket connections.
     */
    int start_listening()
    {
        ctx.server.emplace("User", conf::cfg.pubport, metric_thresholds, conf::cfg.pubmaxsize);
        if (ctx.server->start() == -1)
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
                if (parser.extract_read_request(content) != -1)
                {
                    read_req::populate_read_req_queue(user.pubkey, std::move(content));
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
                    std::string nonce;
                    uint64_t max_lcl_seqno;
                    if (parser.extract_input_container(input_data, nonce, max_lcl_seqno, input_container) != -1)
                    {
                        const int nonce_status = nonce_map.check(user.pubkey, nonce, sig, true);
                        if (nonce_status == 0)
                        {
                            //Add to the submitted input list.
                            user.submitted_inputs.push_back(user_input(
                                std::move(input_container),
                                std::move(sig),
                                user.protocol));
                            return 0;
                        }
                        else
                        {
                            const char *reason = nonce_status == 1 ? msg::usrmsg::REASON_NONCE_EXPIRED : msg::usrmsg::REASON_ALREADY_SUBMITTED;
                            send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, reason, sig);
                            return -1;
                        }
                    }
                    else
                    {
                        send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, sig);
                        return -1;
                    }
                }
                else
                {
                    send_input_status(parser, user.session, msg::usrmsg::STATUS_REJECTED, msg::usrmsg::REASON_BAD_MSG_FORMAT, sig);
                    return -1;
                }
            }
            else if (msg_type == msg::usrmsg::MSGTYPE_STAT)
            {
                std::vector<uint8_t> msg;
                parser.create_status_response(msg, ledger::ctx.get_seq_no(), ledger::ctx.get_lcl());
                user.session.send(msg);
                return 0;
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
     * Send the specified contract input status result via the provided session.
     */
    void send_input_status(const msg::usrmsg::usrmsg_parser &parser, usr::user_comm_session &session,
                           std::string_view status, std::string_view reason, std::string_view input_sig)
    {
        std::vector<uint8_t> msg;
        parser.create_contract_input_status(msg, status, reason, input_sig);
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

        // Decode hex pubkey and get binary pubkey. We are only going to keep
        // the binary pubkey due to reduced memory footprint.
        std::string pubkey;
        pubkey.resize(pubkey_hex.length() / 2);
        util::hex2bin(
            reinterpret_cast<unsigned char *>(pubkey.data()),
            pubkey.length(),
            pubkey_hex);

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
        const auto itr = ctx.users.erase(pubkey);
        return 0;
    }

    /**
     * Validates the provided user input message against all the required criteria.
     * @return The rejection reason if input rejected. NULL if the input can be accepted.
     */
    const char *validate_user_input_submission(const std::string &user_pubkey, const usr::user_input &umsg,
                                               const uint64_t lcl_seq_no, size_t &total_input_len,
                                               std::string &hash, util::buffer_view &input, uint64_t &max_lcl_seqno)
    {
        // Verify the signature of the input_container.
        if (crypto::verify(umsg.input_container, umsg.sig, user_pubkey) == -1)
        {
            LOG_DEBUG << "User message bad signature.";
            return msg::usrmsg::REASON_BAD_SIG;
        }

        std::string nonce;
        msg::usrmsg::usrmsg_parser parser(umsg.protocol);

        std::string input_data;
        if (parser.extract_input_container(input_data, nonce, max_lcl_seqno, umsg.input_container) == -1)
        {
            LOG_DEBUG << "User message bad input format.";
            return msg::usrmsg::REASON_BAD_MSG_FORMAT;
        }

        // Ignore the input if our ledger has passed the input TTL.
        if (max_lcl_seqno <= lcl_seq_no)
        {
            LOG_DEBUG << "User message bad max ledger seq expired.";
            return msg::usrmsg::REASON_MAX_LEDGER_EXPIRED;
        }

        const int nonce_status = nonce_map.check(user_pubkey, nonce, umsg.sig);
        if (nonce_status > 0)
        {
            LOG_DEBUG << (nonce_status == 1 ? "User message nonce expired." : "User message with same nonce/sig already submitted.");
            return (nonce_status == 1 ? msg::usrmsg::REASON_NONCE_EXPIRED : msg::usrmsg::REASON_ALREADY_SUBMITTED);
        }

        // Keep checking the subtotal of inputs extracted so far with the appbill account balance.
        total_input_len += input_data.length();
        if (!verify_appbill_check(user_pubkey, total_input_len))
        {
            LOG_DEBUG << "User message app bill balance exceeded.";
            return msg::usrmsg::REASON_APPBILL_BALANCE_EXCEEDED;
        }

        // Hash is prefixed with the nonce to support user-defined sort order.
        hash = std::move(nonce);
        // Append the hash of the message signature to get the final hash.
        hash.append(crypto::get_hash(umsg.sig));

        // Copy the input data into the input store.
        std::string_view s();
        input = input_store.write_buf(input_data.data(), input_data.size());

        return NULL; // Success. No reject reason.
    }

    /**
     * Executes the appbill and verifies whether the user has enough account balance to process the provided input.
     * @param pubkey User binary pubkey.
     * @param input_len Total bytes length of user input.
     * @return Whether the user is allowed to process the input or not.
     */
    bool verify_appbill_check(std::string_view pubkey, const size_t input_len)
    {
        // If appbill not enabled always green light the input.
        if (conf::cfg.appbill.empty())
            return true;

        // execute appbill in --check mode to verify this user can submit a packet/connection to the network
        // todo: this can be made more efficient, appbill --check can process 7 at a time

        // Fill appbill args
        const int len = conf::cfg.runtime_appbill_args.size() + 4;
        char *execv_args[len];
        for (int i = 0; i < conf::cfg.runtime_appbill_args.size(); i++)
            execv_args[i] = conf::cfg.runtime_appbill_args[i].data();
        char option[] = "--check";
        execv_args[len - 4] = option;
        // add the hex encoded public key as the last parameter
        std::string hexpubkey;
        util::bin2hex(hexpubkey, reinterpret_cast<const unsigned char *>(pubkey.data()), pubkey.size());
        std::string inputsize = std::to_string(input_len);
        execv_args[len - 3] = hexpubkey.data();
        execv_args[len - 2] = inputsize.data();
        execv_args[len - 1] = NULL;

        int pid = fork();
        if (pid == 0)
        {
            // appbill process.
            util::fork_detach();

            // before execution chdir into a valid the latest state data directory that contains an appbill.table
            chdir(conf::ctx.state_rw_dir.c_str());
            int ret = execv(execv_args[0], execv_args);
            std::cerr << errno << ": Appbill process execv failed.\n";
            return false;
        }
        else
        {
            // app bill in check mode takes a very short period of time to execute, typically 1ms
            // so we will blocking wait for it here
            int status = 0;
            waitpid(pid, &status, 0); //todo: check error conditions here
            status = WEXITSTATUS(status);
            if (status != 128 && status != 0)
            {
                // this user's key passed appbill
                return true;
            }
            else
            {
                // user's key did not pass, do not add to user input candidates
                LOG_DEBUG << "Appbill validation failed " << hexpubkey << " return code was " << status;
                return false;
            }
        }
    }

} // namespace usr