#ifndef _HP_USR_
#define _HP_USR_

#include "../pchheader.hpp"
#include "../util.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "user_comm_session.hpp"
#include "user_comm_server.hpp"
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
        std::list<user_input> submitted_inputs;

        // Holds the unprocessed read requests collected from websocket.
        std::list<std::string> read_requests;

        // Holds the websocket session of this user.
        // We don't need to own the session object since the lifetime of user and session are coupled.
        usr::user_comm_session &session;

        // The messaging protocol used by this user.
        const util::PROTOCOL protocol = util::PROTOCOL::JSON;

        /**
         * @param session The web socket session the user is connected to.
         * @param pubkey The public key of the user in binary format.
         */
        connected_user(usr::user_comm_session &session, std::string_view pubkey, util::PROTOCOL protocol)
            : session(session), pubkey(pubkey), protocol(protocol)
        {
        }
    };

    /**
 * The context struct to hold global connected-users and related objects.
 */
    struct connected_context
    {
        // Connected (authenticated) user list.
        // Map key: User pubkey. Value: User info object.
        std::unordered_map<std::string, usr::connected_user> users;
        std::mutex users_mutex; // Mutex for users access race conditions.

        std::optional<usr::user_comm_server> listener;
    };
    extern connected_context ctx;

    int init();

    void deinit();

    int start_listening();

    int verify_challenge(std::string_view message, usr::user_comm_session &session);

    int handle_user_message(connected_user &user, std::string_view message);

    void send_input_status(const msg::usrmsg::usrmsg_parser &parser, usr::user_comm_session &session,
                           std::string_view status, std::string_view reason, std::string_view input_sig);

    int add_user(usr::user_comm_session &session, const std::string &user_pubkey_hex, std::string_view protocol_code);

    int remove_user(const std::string &pubkey);

    const char *validate_user_input_submission(const std::string_view user_pubkey, const usr::user_input &umsg,
                                               const uint64_t lcl_seq_no, size_t &total_input_len,
                                               util::rollover_hashset &recent_user_input_hashes,
                                               std::string &hash, std::string &input, uint64_t &max_lcl_seqno);

    bool verify_appbill_check(std::string_view pubkey, const size_t input_len);

} // namespace usr

#endif