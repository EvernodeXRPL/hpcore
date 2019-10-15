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

namespace usr
{

/**
 * This gets hit every time a client connects to HP via the public port (configured in contract config).
 */
void user_session_handler::on_connect(sock::socket_session *session)
{
    std::cout << "User client connected " << session->address_ << ":" << session->port_ << std::endl;

    // As soon as a user conntects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.

    std::string msg;
    std::string challengeb64;
    usr::create_user_challenge(msg, challengeb64);

    // We init the session unique id to associate with the challenge.
    session->init_uniqueid();

    // Create an entry in pending_challenges for later tracking upon challenge response.
    usr::pending_challenges[session->uniqueid_] = challengeb64;

    session->send(std::move(msg));

    // Set the challenge-issued flag to help later checks in on_message.
    session->flags_.set(util::SESSION_FLAG::USER_CHALLENGE_ISSUED);
}

/**
 * This gets hit every time we receive some data from a client connected to the HP public port.
 */
void user_session_handler::on_message(sock::socket_session *session, std::string &&message)
{
    // First check whether this session is pending challenge.
    // Meaning we have previously issued a challenge to the client,
    if (session->flags_[util::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        // The received message must be the challenge response. We need to verify it.
        auto itr = usr::pending_challenges.find(session->uniqueid_);
        if (itr != usr::pending_challenges.end())
        {
            std::string userpubkey;
            std::string_view original_challenge = itr->second;
            if (usr::verify_user_challenge_response(userpubkey, message, original_challenge) == 0)
            {
                // Challenge singature verification successful.

                // Now check whether this user public key is duplicate.
                if (usr::sessionids.count(userpubkey) == 0)
                {
                    // All good. Unique public key.
                    // Promote the connection from pending-challenges to authenticated users.

                    session->flags_.reset(util::SESSION_FLAG::USER_CHALLENGE_ISSUED); // Clear challenge-issued flag
                    session->flags_.set(util::SESSION_FLAG::USER_AUTHED);             // Set the user-authed flag
                    usr::add_user(session->uniqueid_, userpubkey);                    // Add the user to the global authed user list
                    usr::pending_challenges.erase(session->uniqueid_);                // Remove the stored challenge
                    
                    std::cout << "User connection " << session->uniqueid_ << " authenticated. Public key "
                              << userpubkey << std::endl;
                    return;
                }
                else
                {
                    std::cout << "Duplicate user public key " << session->uniqueid_ << std::endl;
                }
            }
            else
            {
                std::cout << "Challenge verification failed " << session->uniqueid_ << std::endl;
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
            usr::contract_user &user = itr->second;

            //Hand over the bytes into user inbuffer.
            user.inbuffer = std::move(message);

            std::cout << "Collected " << user.inbuffer.length() << " bytes from user " << user.pubkeyb64 << std::endl;
            return;
        }
    }

    // If for any reason we reach this point, we should drop the connection.
    session->close();
    std::cout << "Dropped the user connection " << session->address_ << ":" << session->port_ << std::endl;
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

    std::cout << "User disconnected " << session->uniqueid_ << std::endl;
}

} // namespace usr