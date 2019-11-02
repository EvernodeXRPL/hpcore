#ifndef _HP_USR_USER_INPUT_
#define _HP_USR_USER_INPUT_

#include "../pchheader.hpp"
#include "../crypto.hpp"

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
};

/**
 * Represents a contract input that takes part in consensus.
 */
struct user_candidate_input
{
    std::string userpubkey;
    std::string input;
    const uint64_t maxledgerseqno;

    user_candidate_input(std::string userpubkey, std::string input, uint64_t maxledgerseqno)
    {
        this->userpubkey = std::move(userpubkey);
        this->input = std::move(input);
        this->maxledgerseqno = maxledgerseqno;
    }
}

} // namespace usr

#endif