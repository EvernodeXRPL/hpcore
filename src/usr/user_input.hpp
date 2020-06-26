#ifndef _HP_USR_USER_INPUT_
#define _HP_USR_USER_INPUT_

#include "../pchheader.hpp"

namespace usr
{

/**
 * Represents a signed contract input message a network user has submitted.
 */
struct user_submitted_input
{
    const std::string input_container;
    const std::string sig;

    user_submitted_input(const std::string input_container, const std::string sig)
        : input_container(std::move(input_container)), sig(std::move(sig))
    {
    }

    user_submitted_input(std::string_view input_container, std::string_view sig)
        : input_container(input_container), sig(sig)
    {
    }
};

} // namespace usr

#endif