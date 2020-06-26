#ifndef _HP_USR_
#define _HP_USR_

#include "../pchheader.hpp"
#include "../util.hpp"
#include "../comm/comm_server.hpp"
#include "../comm/comm_session.hpp"
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
        const comm::comm_session &session;

        /**
     * @param session The web socket session the user is connected to.
     * @param pubkey The public key of the user in binary format.
     */
        connected_user(const comm::comm_session &session, std::string_view pubkey)
            : session(session), pubkey(pubkey)
        {
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

        comm::comm_server listener;
    };
    extern connected_context ctx;

    int init();

    void deinit();

    int start_listening();

    int verify_challenge(std::string_view message, comm::comm_session &session);

    int handle_user_message(connected_user &user, std::string_view message);

    void send_input_status(const comm::comm_session &session, std::string_view status, std::string_view reason, std::string_view input_sig);

    int add_user(const comm::comm_session &session, const std::string &pubkey);

    int remove_user(const std::string &sessionid);

    const comm::comm_session *get_session_by_pubkey(const std::string &pubkey);

} // namespace usr

#endif