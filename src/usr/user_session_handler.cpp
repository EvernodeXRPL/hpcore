#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../msg/json/usrmsg_json.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"
#include "user_comm_session.hpp"

namespace jusrmsg = msg::usrmsg::json;

namespace usr
{
    /**
     * This gets hit every time a client connects to HP via the public port (configured in config).
     * @param session connected session.
     * @return returns 0 if connection is successful and user challenge is sent, otherwise -1.
     */
    int handle_user_connect(usr::user_comm_session &session)
    {
        // Allow connection only if the maximum capacity is not reached. 0 means allowing unlimited connections.
        if ((conf::cfg.user.max_connections == 0) || (usr::ctx.users.size() < conf::cfg.user.max_connections))
        {
            LOG_DEBUG << "User client connected " << session.display_name();

            // As soon as a user connects, we issue them a challenge message. We remember the
            // challenge we issued and later verify the user's response with it.
            std::vector<uint8_t> msg;
            jusrmsg::create_user_challenge(msg, session.issued_challenge);
            session.send(msg);

            // Set the challenge-issued value to true.
            session.challenge_status = comm::CHALLENGE_ISSUED;
            return 0;
        }
        else
        {
            LOG_DEBUG << "Dropping the user connection. Maximum user capacity reached. Session: " << session.display_name() << " (limit: " << conf::cfg.user.max_connections << ").";
            return -1;
        }
    }

    /**
     * This gets hit every time we receive some data from a client connected to the HP public port.
     */
    int handle_user_message(usr::user_comm_session &session, std::string_view message)
    {
        // Adding message size to user message characters(bytes) per minute counter.
        session.increment_metric(comm::SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, message.size());

        // First check whether this session is pending challenge.
        // Meaning we have previously issued a challenge to the client.
        if (session.challenge_status == comm::CHALLENGE_ISSUED)
        {
            if (verify_challenge(message, session) == 0)
                return 0;
        }
        // Check whether this session belongs to an authenticated (challenge-verified) user.
        else if (session.challenge_status == comm::CHALLENGE_VERIFIED)
        {
            // Check whether this user is among authenticated users
            // and perform authenticated msg processing.

            const auto itr = ctx.users.find(session.pubkey);
            if (itr != ctx.users.end())
            {
                // This is an authed user.
                connected_user &user = itr->second;
                if (handle_authed_user_message(user, message) != 0)
                {
                    session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
                    LOG_DEBUG << "Bad message from user " << session.display_name();
                }
            }
            else
            {
                session.increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
                LOG_DEBUG << "User session id not found: " << session.display_name();
            }

            return 0;
        }

        // If for any reason we reach this point, we should drop the connection because none of the
        // valid cases match.
        LOG_DEBUG << "Dropping the user connection " << session.display_name();
        ctx.server->violation_tracker.report_violation(session.host_address, session.is_ipv4);
        return -1;
    }

    /**
     * This gets hit every time a client disconnects from the HP public port.
     */
    int handle_user_close(const usr::user_comm_session &session)
    {
        // Session belongs to an authed user.
        if (session.challenge_status == comm::CHALLENGE_VERIFIED)
            remove_user(session.pubkey);

        return 0;
    }

} // namespace usr