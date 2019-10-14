#ifndef _HP_CONTRACT_USER_H_
#define _HP_CONTRACT_USER_H_

#include <string>

namespace usr
{

/**
 * Holds information about an authenticated (challenge-verified) user
 * connected to the HotPocket node.
 */
struct contract_user
{
    std::string pubkeyb64; // Base64 user public key
    std::string inbuffer;  // Holds the user input to be processed by consensus rounds
    std::string outbuffer; // Holds the contract output to be processed by consensus rounds

    // HP --> SC pipe + SC --> HP pipe
    // We keep 2 pipes in single array for easy access.
    // fd[0] used by Smart Contract to read user-input sent by Hot Pocket.
    // fd[1] used by Hot Pocket to write user-input to the smart contract.
    // fd[2] used by Hot Pocket to read output from the smart contract.
    // fd[3] used by Smart Contract to write output back to Hot Pocket.
    int fds[4];

    contract_user(std::string_view _pubkeyb64)
    {
        pubkeyb64 = _pubkeyb64;
    }
};

} // namespace usr

#endif