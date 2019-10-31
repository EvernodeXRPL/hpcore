#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "../util.hpp"
#include "../sock/socket_session.hpp"
#include "../proc.hpp"
#include "../hplog.hpp"
#include "../jsonschema/usrmsg_helpers.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;

namespace usr
{

user_outbound_message::user_outbound_message(std::string &&_msg)
{
    msg = std::move(_msg);
}

// Returns the buffer that should be written to the socket.
std::string_view user_outbound_message::buffer()
{
    return msg;
}

/**
 * This gets hit every time a client connects to HP via the public port (configured in contract config).
 */
void user_session_handler::on_connect(sock::socket_session<user_outbound_message> *session)
{
    LOG_INFO << "User client connected " << session->address << ":" << session->port;

    // As soon as a user connects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.

    // We init the session unique id to associate with the challenge.
    session->init_uniqueid();

    user_outbound_message outmsg(issue_challenge(session->uniqueid));
    session->send(std::move(outmsg));

    // Set the challenge-issued flag to help later checks in on_message.
    session->flags.set(util::SESSION_FLAG::USER_CHALLENGE_ISSUED);
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
    if (session->flags[util::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        if (verify_challenge(message, session))
            return;
    }
    // Check whether this session belongs to an authenticated (challenge-verified) user.
    else if (session->flags[util::SESSION_FLAG::USER_AUTHED])
    {
        // Check whether this user is among authenticated users
        // and perform authenticated msg processing.

        auto itr = ctx.users.find(session->uniqueid);
        if (itr != ctx.users.end())
        {
            // This is an authed user.
            connected_user &user = itr->second;
            handle_user_message(user, message);
            return;
        }
    }

    // If for any reason we reach this point, we should drop the connection.
    session->close();
    LOG_INFO << "Dropped the user connection " << session->address << ":" << session->port;
}

/**
 * This gets hit every time a client disconnects from the HP public port.
 */
void user_session_handler::on_close(sock::socket_session<user_outbound_message> *session)
{
    // Cleanup any resources related to this session.

    // Session is awaiting challenge response.
    if (session->flags[util::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        ctx.pending_challenges.erase(session->uniqueid);
    }
    // Session belongs to an authed user.
    else if (session->flags[util::SESSION_FLAG::USER_AUTHED])
    {
        // Wait for SC process completion before we remove existing user.
        proc::await_contract_execution();
        remove_user(session->uniqueid);
    }

    LOG_INFO << "User disconnected " << session->uniqueid;
}

} // namespace usr