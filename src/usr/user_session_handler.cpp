#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
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
void user_session_handler::on_connect(sock::socket_session *session, error ec)
{
    cout << "User client connected " << session->uniqueid_ << endl;

    // As a soon as a user conntects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.

    string msg;
    string challengeb64;
    usr::create_user_challenge(msg, challengeb64);

    // Create an entry in pending_challenges for later tracking upon challenge response.
    usr::pending_challenges[session->uniqueid_] = challengeb64;

    session->send(make_shared<string>(msg));
}

/**
 * This gets hit every time we receive some data from a client connected to the HP public port.
 */
void user_session_handler::on_message(sock::socket_session *session, std::shared_ptr<std::string const> const &message, error ec)
{
    if (message->length() == 0)
        return;

    // First check whether this session is among pending_challenges.
    auto itr = usr::pending_challenges.find(session->uniqueid_);
    if (itr == usr::pending_challenges.end()) // Does not exist
    {
        // Check whether this user is among authenticated users
        // and perform authenticated msg processing.

        auto itr = usr::users.find(session->uniqueid_);
        if (itr == usr::users.end())
        {
            // Matching user not found.
            // Ideally this code would never get hit. We issue a challenge as soon as a user connects
            // and drops the connection if the challenge fails. so There's no room to receive
            // a message from an untracked anonymous user. But just to be safe we drop the connection
            // in this impossible scenario as well.

            // TODO: Drop the connection
        }
        else
        {
            // Write the message to the user input pipe. SC will read from this pipe when it executes.
            const contract_user &user = itr->second;
            write(user.inpipe[1], message->data(), message->length());
        }
    }
    else
    {
        string userpubkey;
        const string &original_challenge = itr->second;
        if (usr::verify_user_challenge_response(*message, original_challenge, userpubkey) != 0)
        {
            //TODO: Drop the connection
            cout << "User connection " << session->uniqueid_ << " authentication failed. Dropped the connection.\n";
        }
        else
        {
            // Promote the connection from pending-challenges to authenticated users.
            usr::pending_challenges.erase(session->uniqueid_);
            usr::add_user(session->uniqueid_, userpubkey);

            cout << "User connection " << session->uniqueid_ << " authenticated.\n";
        }
    }
}

/**
 * This gets hit every time a client disconnects from the HP public port.
 */
void user_session_handler::on_close(sock::socket_session *session)
{
    // Remove the user from our lists.
    usr::remove_user(session->uniqueid_);
    usr::pending_challenges.erase(session->uniqueid_);

    cout << "User disconnected " << session->uniqueid_ << endl;
}

} // namespace usr