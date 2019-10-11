#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "../util.hpp"
#include "../sock/socket_session.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

using namespace std;

namespace usr
{

/**
 * This gets hit every time a client connects to HP via the public port (configured in contract config).
 */
void user_session_handler::on_connect(sock::socket_session *session)
{
    cout << "User client connected " << session->address_ << ":" << session->port_ << endl;

    // As a soon as a user conntects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.

    string msg;
    string challengeb64;
    usr::create_user_challenge(msg, challengeb64);

    // Create an entry in pending_challenges for later tracking upon challenge response.
    usr::pending_challenges[session->uniqueid_] = challengeb64;

    // TODO: This needs to be reviewed to optimise passing the message.
    session->send(make_shared<string>(msg));

    // Set the challenge-issued flag and session uniqueid to help later checks in on_message.
    session->flags_.set(util::SESSION_FLAG::USER_CHALLENGE_ISSUED);
    session->init_uniqueid();
}

/**
 * This gets hit every time we receive some data from a client connected to the HP public port.
 */
void user_session_handler::on_message(sock::socket_session *session, const std::string &message)
{
    // First check whether this session is pending challenge.
    // Meaning we have previously issued a challenge to the client,
    if (session->flags_[util::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        // The received message must be the challenge response. We need to verify it.

        auto itr = usr::pending_challenges.find(session->uniqueid_);
        if (itr != usr::pending_challenges.end())
        {
            string userpubkey;
            const string &original_challenge = itr->second;
            if (usr::verify_user_challenge_response(message, original_challenge, userpubkey) == 0)
            {
                // Challenge verification successful.
                // Promote the connection from pending-challenges to authenticated users.

                session->flags_.reset(util::SESSION_FLAG::USER_CHALLENGE_ISSUED); // Clear challenge-issued flag
                session->flags_.set(util::SESSION_FLAG::USER_AUTHED);             // Set the user-authed flag
                usr::pending_challenges.erase(session->uniqueid_);                // Remove the stored challenge
                usr::add_user(session->uniqueid_, userpubkey);                    // Add the user to the global authed user list

                cout << "User connection " << session->uniqueid_ << " authenticated.\n";
                return;
            }
        }
    }
    // Check whether this session belongs to an authenticated (challenge-verified) user.
    else if (session->flags_[util::SESSION_FLAG::USER_AUTHED])
    {
        // Check whether this user is among authenticated users
        // and perform authenticated msg processing.

        auto itr = usr::users.find(session->uniqueid_);
        if (itr != usr::users.end())
        {
            // This is an authed user.
            // Write the message to the user input pipe. SC will read from this pipe when it executes.
            const contract_user &user = itr->second;
            write(user.inpipe[1], message.data(), message.length());
            cout << "User " << user.pubkeyb64 << " wrote " << message.length() << " bytes to contract input.\n";
            return;
        }
    }

    // If for any reason we reach this point, we should drop the connection.
    session->close();
    cout << "Drop the connection " << session->address_ << ":" << session->port_ << endl;
}

/**
 * This gets hit every time a client disconnects from the HP public port.
 */
void user_session_handler::on_close(sock::socket_session *session)
{
    // Cleanup any resources related to this session.

    // Session is awaiting challenge response.
    if (session->flags_[util::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        usr::pending_challenges.erase(session->uniqueid_);
    }
    // Session belongs to an authed user.
    else if (session->flags_[util::SESSION_FLAG::USER_AUTHED])
    {
        usr::remove_user(session->uniqueid_);
    }

    cout << "User disconnected " << session->uniqueid_ << endl;
}

} // namespace usr