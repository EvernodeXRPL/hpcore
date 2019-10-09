#ifndef _HP_USR_H_
#define _HP_USR_H_

//Length of user random challenge bytes.
#define USER_CHALLENGE_LEN 16

//Message type for the user challenge.
#define MSG_PUBLIC_CHALLENGE "public_challenge"

//Message type for the user challenge response.
#define MSG_CHALLENGE_RESP "challenge_response"

#include <cstdio>
#include <vector>
#include <map>
#include "../util.h"

using namespace std;
using namespace util;

/**
 * Maintains the global user list with pending input outputs and manages user connections.
 */
namespace usr
{

/**
 * Global authenticated (challenge-verified) user list.
 */
extern map<string, ContractUser> users;

/**
 * Initializes the usr subsystem. Must be called once during application startup.
 */
int init();

/**
 * Constructs user challenge message json and the challenge string required for
 * initial user challenge handshake. This gets called when a user gets establishes
 * a web sockets connection to HP.
 * 
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "version": "<HP version>",
 *              "type": "public_challenge",
 *              "challenge": "<base64 challenge string>"
 *            }
 * @param challenge String reference to copy the generated base64 challenge string into.
 */ 
void create_user_challenge(string &msg, string &challengeb64);

/**
 * Verifies the user challenge response with the original challenge issued to the user
 * and the user public contained in the response.
 * 
 * @param response The response bytes to verify. This will be parsed as json.
 *                 Accepted response format:
 *                 {
 *                   "type": "challenge_response",
 *                   "challenge": "<original base64 challenge the user received>",
 *                   "sig": "<Base64 signature of the challenge>",
 *                   "pubkey": "<Base64 public key of the user>"
 *                 }
 * @param original_challenge The original base64 challenge string issued to the user.
 * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
 */
int verify_user_challenge_response(const string &response, const string &original_challenge, string &extracted_pubkey);

/**
 * Adds the specified public key into the global user list.
 * This should get called after the challenge handshake is verified.
 * 
 * @return 0 on successful additions. -1 on failure.
 */
int add_user(const string &pubkeyb64);

/**
 * Removes the specified public key from the global user list.
 * This must get called when a user disconnects from HP.
 * 
 * @return 0 on successful removals. -1 on failure.
 */
int remove_user(const string &pubkeyb64);

/**
 * Read all per-user outputs produced by the contract process and store them in
 * the user buffer for later processing.
 * 
 * @return 0 on success. -1 on failure.
 */
int read_contract_user_outputs();

} // namespace usr

#endif