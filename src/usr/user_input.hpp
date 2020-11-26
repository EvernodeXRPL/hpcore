#ifndef _HP_USR_USER_INPUT_
#define _HP_USR_USER_INPUT_

#include "../pchheader.hpp"
#include "../util/util.hpp"

namespace usr
{

    /**
 * Represents a signed contract input message a network user has submitted.
 */
    struct user_input
    {
        const std::string input_container;
        const std::string sig;
        const util::PROTOCOL protocol; // The encoding protocol used for the input container.

        user_input(const std::string input_container, const std::string sig, const util::PROTOCOL protocol)
            : input_container(std::move(input_container)), sig(std::move(sig)), protocol(protocol)
        {
        }

        user_input(std::string_view input_container, std::string_view sig, const util::PROTOCOL protocol)
            : input_container(input_container), sig(sig), protocol(protocol)
        {
        }
    };

    struct raw_user_input
    {
        const std::string pubkey;
        const usr::user_input user_input;

        raw_user_input(const std::string pubkey, const usr::user_input user_input)
            : pubkey(pubkey), user_input(user_input)
        {
        }

        raw_user_input(std::string_view pubkey, const usr::user_input user_input)
            : pubkey(pubkey), user_input(user_input)
        {
        }
    };

} // namespace usr

#endif