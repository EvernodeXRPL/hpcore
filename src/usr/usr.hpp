#ifndef _HP_USR_
#define _HP_USR_

#include "../pchheader.hpp"
#include "../util/util.hpp"
#include "../util/h32.hpp"
#include "../util/rollover_hashset.hpp"
#include "../util/buffer_store.hpp"
#include "../msg/usrmsg_parser.hpp"
#include "user_comm_session.hpp"
#include "user_comm_server.hpp"
#include "user_input.hpp"
#include "user_common.hpp"

/**
 * Maintains the global user list with pending input outputs and manages user connections.
 */
namespace usr
{
    constexpr uint16_t MAX_USER_COUNT = 64; // Maximum number of user.

    /**
     * Holds information about an authenticated (challenge-verified) user
     * connected to the HotPocket node.
     */
    struct connected_user
    {
        // User binary public key
        const std::string pubkey;

        // Holds the unprocessed user inputs collected from websocket.
        std::list<submitted_user_input> submitted_inputs;

        // Total input bytes collected which are pending to be subjected to consensus.
        size_t collected_input_size = 0;

        // User's notification subscription toggles.
        bool subscriptions[3];

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
            : pubkey(pubkey), session(session), protocol(protocol)
        {
            // Default subscriptions.
            subscriptions[NOTIFICATION_CHANNEL::UNL_CHANGE] = false;
            subscriptions[NOTIFICATION_CHANNEL::LEDGER_EVENT] = false;
            subscriptions[NOTIFICATION_CHANNEL::HEALTH_STAT] = false;
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

        std::optional<usr::user_comm_server> server;
    };

    struct input_status_response
    {
        const std::string input_hash;
        const char *reject_reason = NULL;
        const uint64_t ledger_seq_no = 0;
        const util::h32 ledger_hash = util::h32_empty;
    };

    extern connected_context ctx;
    extern util::buffer_store input_store;

    int init();

    void deinit();

    int start_listening();

    int verify_challenge(std::string_view message, usr::user_comm_session &session);

    int handle_authed_user_message(connected_user &user, std::string_view message);

    void send_input_status_responses(const std::unordered_map<std::string, std::vector<input_status_response>> &responses,
                                     const uint64_t ledger_seq_no = 0, const util::h32 &ledger_hash = util::h32_empty);

    void send_debug_shell_response(const msg::usrmsg::usrmsg_parser &parser, usr::user_comm_session &session, std::string_view reply_for,
                            std::string_view status, std::string_view content, std::string_view reason = "");

    void send_input_status(const msg::usrmsg::usrmsg_parser &parser, usr::user_comm_session &session,
                           std::string_view status, std::string_view reason, std::string_view input_hash,
                           const uint64_t ledger_seq_no = 0, const util::h32 &ledger_hash = util::h32_empty);

    int add_user(usr::user_comm_session &session, const std::string &user_pubkey_hex, std::string_view protocol_code);

    int remove_user(const std::string &pubkey);

    const char *extract_submitted_input(const std::string &user_pubkey, const usr::submitted_user_input &submitted, usr::extracted_user_input &extracted);

    const char *validate_user_input_submission(const std::string &user_pubkey, const usr::extracted_user_input &extracted_input,
                                               const uint64_t lcl_seq_no, size_t &total_input_size, std::string &ordered_hash, util::buffer_view &input);

    void dispatch_change_events();

} // namespace usr

#endif