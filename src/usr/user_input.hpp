#ifndef _HP_USR_USER_INPUT_
#define _HP_USR_USER_INPUT_

#include "../pchheader.hpp"

namespace usr
{

/**
 * Represents a signed contract input message a network user has submitted.
 */
struct user_submitted_message
{
    std::string content;
    std::string sig;

    user_submitted_message(std::string content, std::string sig)
    {
        this->content = std::move(content);
        this->sig = std::move(sig);
    }

    user_submitted_message(std::string_view content, std::string_view sig)
    {
        this->content = content;
        this->sig = sig;
    }
};

} // namespace usr

#endif