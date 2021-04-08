#ifndef _HP_USR_USER_INPUT_
#define _HP_USR_USER_INPUT_

#include "../pchheader.hpp"
#include "../util/util.hpp"

namespace usr
{

    /**
     * Represents a signed contract input message a network user has submitted.
     */
    struct submitted_user_input
    {
        const std::string input_container;
        const std::string sig;
        const util::PROTOCOL protocol; // The message protocol used by the user.
    };

    struct extracted_user_input
    {
        std::string input;
        std::string nonce;
        uint64_t max_ledger_seq_no;
        std::string sig;

        // Comparison operator used for sorting user's inputs in nonce order.
        bool operator<(const extracted_user_input &other)
        {
            return nonce < other.nonce;
        }
    };

} // namespace usr

#endif