#ifndef _HP_USR_H_
#define _HP_USR_H_

#include <cstdio>
#include <string_view>
#include <unordered_map>
#include "../util.hpp"

/**
 * Maintains the global user list with pending input outputs and manages user connections.
 */
namespace usr
{

/**
 * Holds information about an authenticated (challenge-verified) user
 * connected to the HotPocket node.
 */
struct contract_user
{
    // Base64 user public key
    std::string pubkeyb64;
    
    // Holds the user input to be processed by consensus rounds
    std::string inbuffer;

    // Holds the contract output to be processed by consensus rounds
    std::string outbuffer;

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

/**
 * Enum used to differenciate pipe fds maintained for user/SC communication.
 */
enum USERFDTYPE
{
    // Used by Smart Contract to read user-input sent by Hot Pocket
    SCREAD = 0,
    // Used by Hot Pocket to write user-input to the smart contract.
    HPWRITE = 1,
    // Used by Hot Pocket to read output from the smart contract.
    HPREAD = 2,
    // Used by Smart Contract to write output back to Hot Pocket.
    SCWRITE = 3
};

/**
 * Global authenticated (challenge-verified) user list.
 */
extern std::unordered_map<std::string, usr::contract_user> users;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 * Map key: User socket session id (<ip:port>)
 */
extern std::unordered_map<std::string, std::string> sessionids;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 */
extern std::unordered_map<std::string, std::string> pending_challenges;

int init();

void deinit();

void create_user_challenge(std::string &msg, std::string &challengeb64);

int verify_user_challenge_response(std::string &extracted_pubkeyb64, std::string_view response, std::string_view original_challenge);

int add_user(const std::string &sessionid, const std::string &pubkeyb64);

int remove_user(const std::string &sessionid);

void start_listening();

void stop_listening();

} // namespace usr

#endif