#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "../sock/socket_session.hpp"
#include "../sock/socket_message.hpp"
#include "../bill/corebill.h"
#include "usr.hpp"
#include "user_session_handler.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;

namespace usr
{

/**
 * This gets hit every time a client connects to HP via the public port (configured in contract config).
 */
void user_session_handler::on_connect(sock::socket_session<user_outbound_message> *session)
{
    if (conf::cfg.pubmaxcons > 0 && ctx.users.size() >= conf::cfg.pubmaxcons)
    {
        session->close();
        LOG_DBG << "Max user connections reached. Dropped connection " << session->uniqueid;
        return;
    }

    LOG_DBG << "User client connected " << session->uniqueid;

    // As soon as a user connects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.
    session->send(
        user_outbound_message(issue_challenge(session->uniqueid)));

    // Set the challenge-issued flag to help later checks in on_message.
    session->flags.set(sock::SESSION_FLAG::USER_CHALLENGE_ISSUED);
}

/**
 * This gets hit every time we receive some data from a client connected to the HP public port.
 */
void user_session_handler::on_message(
    sock::socket_session<user_outbound_message> *session,
    std::string_view message)
{
    // First check whether this session is pending challenge.
    // Meaning we have previously issued a challenge to the client,
    if (session->flags[sock::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        if (verify_challenge(message, session) == 0)
            return;
    }
    // Check whether this session belongs to an authenticated (challenge-verified) user.
    else if (session->flags[sock::SESSION_FLAG::USER_AUTHED])
    {
        // Check whether this user is among authenticated users
        // and perform authenticated msg processing.

        const auto itr = ctx.users.find(session->uniqueid);
        if (itr != ctx.users.end())
        {
            // This is an authed user.
            connected_user &user = itr->second;
            if (handle_user_message(user, message) != 0)
            {
                session->increment_metric(sock::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
                LOG_DBG << "Bad message from user " << session->uniqueid;
            }
        }
        else
        {
            session->increment_metric(sock::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
            LOG_DBG << "User session id not found: " << session->uniqueid;
        }

        return;
    }

    // If for any reason we reach this point, we should drop the connection because none of the
    // valid cases match.
    session->close();
    LOG_DBG << "Dropped the user connection " << session->uniqueid;
    corebill::report_violation(session->address);
}

/**
 * This gets hit every time a client disconnects from the HP public port.
 */
void user_session_handler::on_close(sock::socket_session<user_outbound_message> *session)
{
    // Cleanup any resources related to this session.

    // Session is awaiting challenge response.
    if (session->flags[sock::SESSION_FLAG::USER_CHALLENGE_ISSUED])
        ctx.pending_challenges.erase(session->uniqueid);

    // Session belongs to an authed user.
    else if (session->flags[sock::SESSION_FLAG::USER_AUTHED])
        remove_user(session->uniqueid);

    LOG_DBG << "User disconnected " << session->uniqueid;
}

} // namespace usr