#include <rapidjson/document.h>
#include <sodium.h>
#include "../util.hpp"
#include "../crypto.hpp"
#include "../hplog.hpp"
#include "usrmsg_helpers.hpp"

namespace jsonschema::usrmsg
{

static const char *SCHEMA_VERSION = "0.1";

// These fields are used on json messages response validation.
static const char *FLD_TYPE = "type";
static const char *FLD_CHALLENGE = "challenge";
static const char *FLD_SIG = "sig";
static const char *FLD_PUBKEY = "pubkey";
static const char *FLD_INPUT = "input";
static const char *FLD_CONTENT = "content";
static const char *FLD_NONCE = "nonce";

// Message types
static const char *MSGTYPE_CHALLENGE = "public_challenge";
static const char *MSGTYPE_CHALLENGE_RESP = "challenge_response";
static const char *MSGTYPE_CONTRACT_INPUT = "contract_input";

// Length of user random challenge bytes.
static const size_t CHALLENGE_LEN = 16;

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
 *              "challenge": "<hex challenge string>"
 *            }
 * @param challenge String reference to copy the generated hex challenge string into.
 */
void create_user_challenge(std::string &msg, std::string &challengehex)
{
    // Use libsodium to generate the random challenge bytes.
    unsigned char challenge_bytes[CHALLENGE_LEN];
    randombytes_buf(challenge_bytes, CHALLENGE_LEN);

    // We pass the hex challenge string separately to the caller even though
    // we also include it in the challenge msg as well.

    util::bin2hex(challengehex, challenge_bytes, CHALLENGE_LEN);

    // Construct the challenge msg json.
    // We do not use RapidJson here in favour of performance because this is a simple json message.

    // Since we know the rough size of the challenge massage we reserve adequate amount for the holder.
    // Only Hot Pocket version number is variable length. Therefore message size is roughly 95 bytes
    // so allocating 128bits for heap padding.
    msg.reserve(128);
    msg.append("{\"version\":\"")
        .append(SCHEMA_VERSION)
        .append("\",\"")
        .append(FLD_TYPE)
        .append("\":\"")
        .append(MSGTYPE_CHALLENGE)
        .append("\",\"")
        .append(FLD_CHALLENGE)
        .append("\":\"")
        .append(challengehex)
        .append("\"}");
}

/**
 * Verifies the user challenge response with the original challenge issued to the user
 * and the user public key contained in the response.
 * 
 * @param extracted_pubkeyhex The hex public key extracted from the response. 
 * @param response The response bytes to verify. This will be parsed as json.
 *                 Accepted response format:
 *                 {
 *                   "type": "challenge_response",
 *                   "challenge": "<original hex challenge the user received>",
 *                   "sig": "<hex signature of the challenge>",
 *                   "pubkey": "<hex public key of the user>"
 *                 }
 * @param original_challenge The original hex challenge string issued to the user.
 * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
 */
int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge)
{
    // We load response raw bytes into json document.
    rapidjson::Document d;

    // Because we project the response message directly from the binary socket buffer in a zero-copy manner, the response
    // string is not null terminated. 'kParseStopWhenDoneFlag' avoids rapidjson error in this case.
    d.Parse<rapidjson::kParseStopWhenDoneFlag>(response.data());
    if (d.HasParseError())
    {
        LOG_INFO << "Challenge response json parsing failed.";
        return -1;
    }

    // Validate msg type.
    if (!d.HasMember(FLD_TYPE) || d[FLD_TYPE] != MSGTYPE_CHALLENGE_RESP)
    {
        LOG_INFO << "User challenge response type invalid. 'challenge_response' expected.";
        return -1;
    }

    // Compare the response challenge string with the original issued challenge.
    if (!d.HasMember(FLD_CHALLENGE) || d[FLD_CHALLENGE] != original_challenge.data())
    {
        LOG_INFO << "User challenge response challenge invalid.";
        return -1;
    }

    // Check for the 'sig' field existence.
    if (!d.HasMember(FLD_SIG) || !d[FLD_SIG].IsString())
    {
        LOG_INFO << "User challenge response signature invalid.";
        return -1;
    }

    // Check for the 'pubkey' field existence.
    if (!d.HasMember(FLD_PUBKEY) || !d[FLD_PUBKEY].IsString())
    {
        LOG_INFO << "User challenge response public key invalid.";
        return -1;
    }

    // Verify the challenge signature. We do this last due to signature verification cost.
    std::string_view pubkeysv = util::getsv(d[FLD_PUBKEY]);
    if (crypto::verify_hex(
            original_challenge,
            util::getsv(d[FLD_SIG]),
            pubkeysv) != 0)
    {
        LOG_INFO << "User challenge response signature verification failed.";
        return -1;
    }

    extracted_pubkeyhex = pubkeysv;

    return 0;
}

} // namespace jsonschema::usrmsg