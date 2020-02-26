#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "../bill/corebill.h"
#include "usr.hpp"
#include "user_session_handler.hpp"

namespace usr
{

/**
 * This gets hit every time a client connects to HP via the public port (configured in contract config).
 */
int user_session_handler::on_connect(comm::comm_session &session) const
{
    if (conf::cfg.pubmaxcons > 0 && ctx.users.size() >= conf::cfg.pubmaxcons)
    {
        LOG_DBG << "Max user connections reached. Dropped connection " << session.uniqueid;
        return -1;
    }

    LOG_DBG << "User client connected " << session.uniqueid;

    // As soon as a user connects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.
    session.send(issue_challenge(session.uniqueid));

    // Set the challenge-issued flag to help later checks in on_message.
    session.flags.set(comm::SESSION_FLAG::USER_CHALLENGE_ISSUED);

    return 0;
}

/**
 * This gets hit every time we receive some data from a client connected to the HP public port.
 */
int user_session_handler::on_message(comm::comm_session &session, std::string_view message) const
{
    // First check whether this session is pending challenge.
    // Meaning we have previously issued a challenge to the client,
    if (session.flags[comm::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        if (verify_challenge(message, session) == 0)
            return 0;
    }
    // Check whether this session belongs to an authenticated (challenge-verified) user.
    else if (session.flags[comm::SESSION_FLAG::USER_AUTHED])
    {
        // Check whether this user is among authenticated users
        // and perform authenticated msg processing.

        const auto itr = ctx.users.find(session.uniqueid);
        if (itr != ctx.users.end())
        {
            // This is an authed user.
            connected_user &user = itr->second;
            if (handle_user_message(user, message) != 0)
            {
                session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
                LOG_DBG << "Bad message from user " << session.uniqueid;
            }
        }
        else
        {
            session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
            LOG_DBG << "User session id not found: " << session.uniqueid;
        }

        return 0;
    }

    // If for any reason we reach this point, we should drop the connection because none of the
    // valid cases match.
    LOG_DBG << "Dropping the user connection " << session.uniqueid;
    corebill::report_violation(session.address);
    return -1;
}

/**
 * This gets hit every time a client disconnects from the HP public port.
 */
void user_session_handler::on_close(const comm::comm_session &session) const
{
    // Cleanup any resources related to this session.

    // Session is awaiting challenge response.
    if (session.flags[comm::SESSION_FLAG::USER_CHALLENGE_ISSUED])
        ctx.pending_challenges.erase(session.uniqueid);

    // Session belongs to an authed user.
    else if (session.flags[comm::SESSION_FLAG::USER_AUTHED])
        remove_user(session.uniqueid);
}

} // namespace usr