#include "../pchheader.hpp"
#include "../util/util.hpp"
#include "user_comm_session.hpp"
#include "user_session_handler.hpp"

namespace usr
{
    int user_comm_session::handle_connect()
    {
        return usr::handle_user_connect(*this);
    }

    int user_comm_session::handle_message(std::string_view msg)
    {
        return usr::handle_user_message(*this, msg);
    }

    void user_comm_session::handle_close()
    {
        usr::handle_user_close(*this);
    }

    /**
     * Returns printable name for the session based on uniqueid (used for logging).
     */
    const std::string user_comm_session::display_name()
    {
        if (challenge_status == comm::CHALLENGE_STATUS::CHALLENGE_VERIFIED)
        {
            // User sessions use binary pubkey as unique id. So we need to convert to hex.
            std::string hex;
            util::bin2hex(hex,
                          reinterpret_cast<const unsigned char *>(uniqueid.data()),
                          uniqueid.length());
            return hex.substr(2, 10) + (is_inbound ? ":in" : ":out"); // Skipping first 2 bytes key type prefix.
        }

        return comm_session::display_name();
    }

} // namespace usr