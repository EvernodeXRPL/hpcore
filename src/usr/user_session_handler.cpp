#include <iostream>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include "../util.hpp"
#include "../sock/socket_session.hpp"
#include "../proc.hpp"
#include "../hplog.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"

namespace net = boost::asio;
namespace beast = boost::beast;

using tcp = net::ip::tcp;
using error = boost::system::error_code;

namespace usr
{

user_outbound_message::user_outbound_message(std::string &&_msg)
{
    msg = std::move(_msg);
}

std::string_view user_outbound_message::buffer()
{
    return std::string_view(msg.data(), msg.size());
}

/**
 * This gets hit every time a client connects to HP via the public port (configured in contract config).
 */
void user_session_handler::on_connect(sock::socket_session<user_outbound_message> *session)
{
    LOG_INFO << "User client connected " << session->address_ << ":" << session->port_;

    // As soon as a user connects, we issue them a challenge message. We remember the
    // challenge we issued and later verifies the user's response with it.

    std::string msgstr;
    std::string challengehex;
    usr::create_user_challenge(msgstr, challengehex);

    // We init the session unique id to associate with the challenge.
    session->init_uniqueid();

    // Create an entry in pending_challenges for later tracking upon challenge response.
    usr::pending_challenges[session->uniqueid_] = challengehex;

    user_outbound_message outmsg(std::move(msgstr));
    session->send(std::move(outmsg));

    // Set the challenge-issued flag to help later checks in on_message.
    session->flags_.set(util::SESSION_FLAG::USER_CHALLENGE_ISSUED);
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
    if (session->flags_[util::SESSION_FLAG::USER_CHALLENGE_ISSUED])
    {
        // The received message must be the challenge response. We need to verify it.
        auto itr = usr::pending_challenges.find(session->uniqueid_);
        if (itr != usr::pending_challenges.end())
        {
            std::string userpubkeyhex;
            std::string_view original_challenge = itr->second;
            if (usr::verify_user_challenge_response(userpubkeyhex, message, original_challenge) == 0)
            {
                // Challenge singature verification successful.

                // Decode hex pubkey and get binary pubkey. We area only going to keep
                // the binary pubkey due to reduced memory footprint.
                std::string userpubkey;
                userpubkey.resize(userpubkeyhex.length() / 2);
                util::hex2bin(
                    reinterpret_cast<unsigned char *>(userpubkey.data()),
                    userpubkey.length(),
                    userpubkeyhex);

                // Now check whether this user public key is duplicate.
                if (usr::sessionids.count(userpubkey) == 0)
                {
                    // All good. Unique public key.
                    // Promote the connection from pending-challenges to authenticated users.

                    session->flags_.reset(util::SESSION_FLAG::USER_CHALLENGE_ISSUED); // Clear challenge-issued flag
                    session->flags_.set(util::SESSION_FLAG::USER_AUTHED);             // Set the user-authed flag
                    usr::add_user(session, userpubkey);                               // Add the user to the global authed user list
                    usr::pending_challenges.erase(session->uniqueid_);                // Remove the stored challenge

                    LOG_INFO << "User connection " << session->uniqueid_ << " authenticated. Public key "
                             << userpubkeyhex;
                    return;
                }
                else
                {
                    LOG_INFO << "Duplicate user public key " << session->uniqueid_;
                }
            }
            else
            {
                LOG_INFO << "Challenge verification failed " << session->uniqueid_;
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
            usr::connected_user &user = itr->second;

            //Append the bytes into connected user input buffer.
            user.inbuffer.append(message);

            LOG_DBG << "Collected " << user.inbuffer.length() << " bytes from user";
            return;
        }
    }

    // If for any reason we reach this point, we should drop the connection.
    session->close();
    LOG_INFO << "Dropped the user connection " << session->address_ << ":" << session->port_;
}

/**
 * This gets hit every time a client disconnects from the HP public port.
 */
void user_session_handler::on_close(sock::socket_session<user_outbound_message> *session)
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
        // Wait for SC process completion before we remove existing user.
        proc::await_contract_execution();
        usr::remove_user(session->uniqueid_);
    }

    LOG_INFO << "User disconnected " << session->uniqueid_;
}

} // namespace usr