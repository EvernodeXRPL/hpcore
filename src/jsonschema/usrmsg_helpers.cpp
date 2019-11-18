#include "../pchheader.hpp"
#include "../util.hpp"
#include "../crypto.hpp"
#include "../cons/cons.hpp"
#include "../hplog.hpp"
#include "usrmsg_helpers.hpp"

namespace jsonschema::usrmsg
{

// User JSON message schema version
constexpr const char *SCHEMA_VERSION = "0.1";

// Separators
constexpr const char *SEP_COMMA = "\",\"";
constexpr const char *SEP_COLON = "\":\"";
constexpr const char *SEP_COMMA_NOQUOTE = ",\"";
constexpr const char *SEP_COLON_NOQUOTE = "\":";

// Message field names
const char *const FLD_VERSION = "version";
constexpr const char *FLD_TYPE = "type";
constexpr const char *FLD_CHALLENGE = "challenge";
constexpr const char *FLD_SIG = "sig";
constexpr const char *FLD_PUBKEY = "pubkey";
constexpr const char *FLD_INPUT = "input";
constexpr const char *FLD_MAX_LED_SEQ = "max_ledger_seqno";
constexpr const char *FLD_CONTENT = "content";
constexpr const char *FLD_NONCE = "nonce";
constexpr const char *FLD_LCL = "lcl";
constexpr const char *FLD_LCL_SEQ = "lcl_seqno";

// Length of user random challenge bytes.
const size_t CHALLENGE_LEN = 16;

/**
 * Constructs user challenge message json and the challenge string required for
 * initial user challenge handshake. This gets called when a user gets establishes
 * a web sockets connection to HP.
 * 
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "version": "<protocol version>",
 *              "type": "public_challenge",
 *              "challenge": "<hex challenge string>"
 *            }
 * @param challengehex String reference to copy the generated hex challenge string into.
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
    // Only Hot Pocket version number is variable length. Therefore message size is roughly 90 bytes
    // so allocating 128bytes for heap padding.
    msg.reserve(128);
    msg.append("{\"")
        .append(FLD_VERSION)
        .append(SEP_COLON)
        .append(SCHEMA_VERSION)
        .append(SEP_COMMA)
        .append(FLD_TYPE)
        .append(SEP_COLON)
        .append(MSGTYPE_CHALLENGE)
        .append(SEP_COMMA)
        .append(FLD_CHALLENGE)
        .append(SEP_COLON)
        .append(challengehex)
        .append("\"}");
}

/**
 * Constructs a status response message.
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "type": "stat_resp",
 *              "lcl": "<lcl id>"
 *              "lcl_seqno": <integer>
 *            }
 */
void create_status_response(std::string &msg)
{
    msg.reserve(128);
    msg.append("{\"")
        .append(FLD_TYPE)
        .append(SEP_COLON)
        .append(MSGTYPE_STAT_RESP)
        .append(SEP_COMMA)
        .append(FLD_LCL)
        .append(SEP_COLON)
        .append(cons::ctx.lcl)
        .append(SEP_COMMA)
        .append(FLD_LCL_SEQ)
        .append(SEP_COLON_NOQUOTE)
        .append(std::to_string(cons::ctx.led_seq_no))
        .append("}");
}

/**
 * Constructs a contract output container message.
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "type": "contract_output",
 *              "lcl": "<lcl id>"
 *              "lcl_seqno": <integer>,
 *              "content": "<hex encoded contract output>"
 *            }
 * @param content The contract binary output content to be put in the message.
 */
void create_contract_output_container(std::string &msg, std::string_view content)
{
    std::string contenthex;
    util::bin2hex(
        contenthex,
        reinterpret_cast<const unsigned char *>(content.data()),
        content.length());

    msg.reserve(256);
    msg.append("{\"")
        .append(FLD_TYPE)
        .append(SEP_COLON)
        .append(MSGTYPE_CONTRACT_OUTPUT)
        .append(SEP_COMMA)
        .append(FLD_LCL)
        .append(SEP_COLON)
        .append(cons::ctx.lcl)
        .append(SEP_COMMA)
        .append(FLD_LCL_SEQ)
        .append(SEP_COLON_NOQUOTE)
        .append(std::to_string(cons::ctx.led_seq_no))
        .append(SEP_COMMA_NOQUOTE)
        .append(FLD_CONTENT)
        .append(SEP_COLON)
        .append(contenthex)
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
 *                   "type": "challenge_resp",
 *                   "challenge": "<original hex challenge the user received>",
 *                   "sig": "<hex signature of the challenge>",
 *                   "pubkey": "<hex public key of the user>"
 *                 }
 * @param original_challenge The original hex challenge string issued to the user.
 * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
 */
int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge)
{
    rapidjson::Document d;
    if (parse_user_message(d, response) != 0)
        return -1;

    // Validate msg type.
    if (d[FLD_TYPE] != MSGTYPE_CHALLENGE_RESP)
    {
        LOG_DBG << "User challenge response type invalid. 'challenge_response' expected.";
        return -1;
    }

    // Compare the response challenge string with the original issued challenge.
    if (!d.HasMember(FLD_CHALLENGE) || d[FLD_CHALLENGE] != original_challenge.data())
    {
        LOG_DBG << "User challenge response challenge invalid.";
        return -1;
    }

    // Check for the 'sig' field existence.
    if (!d.HasMember(FLD_SIG) || !d[FLD_SIG].IsString())
    {
        LOG_DBG << "User challenge response signature invalid.";
        return -1;
    }

    // Check for the 'pubkey' field existence.
    if (!d.HasMember(FLD_PUBKEY) || !d[FLD_PUBKEY].IsString())
    {
        LOG_DBG << "User challenge response public key invalid.";
        return -1;
    }

    // Verify the challenge signature. We do this last due to signature verification cost.
    std::string_view pubkeysv = util::getsv(d[FLD_PUBKEY]);
    if (crypto::verify_hex(
            original_challenge,
            util::getsv(d[FLD_SIG]),
            pubkeysv) != 0)
    {
        LOG_DBG << "User challenge response signature verification failed.";
        return -1;
    }

    extracted_pubkeyhex = pubkeysv;

    return 0;
}

/**
 * Extracts a signed input container message sent by user.
 * 
 * @param extracted_content The content extracted from the message.
 * @param extracted_sig The binary signature extracted from the message. 
 * @param d The json document holding the input container.
 *          Accepted signed input container format:
 *          {
 *            "type": "contract_input",
 *            "content": "<stringified json input container message>",
 *            "sig": "<hex encoded signature of the content>"
 *          }
 * @return 0 on successful extraction. -1 for failure.
 */
int extract_signed_input_container(
    std::string &extracted_content, std::string &extracted_sig, const rapidjson::Document &d)
{
    if (!d.HasMember(FLD_CONTENT) || !d.HasMember(FLD_SIG))
    {
        LOG_DBG << "User signed input required fields missing.";
        return -1;
    }

    if (!d[FLD_CONTENT].IsString() || !d[FLD_SIG].IsString())
    {
        LOG_DBG << "User signed input invaid field values.";
        return -1;
    }

    // Verify the signature of the content.

    const std::string content(d[FLD_CONTENT].GetString(), d[FLD_CONTENT].GetStringLength());

    const std::string_view sighex(d[FLD_SIG].GetString(), d[FLD_SIG].GetStringLength());
    std::string sig;
    sig.resize(crypto_sign_ed25519_BYTES);
    util::hex2bin(reinterpret_cast<unsigned char *>(sig.data()), sig.length(), sighex);

    extracted_content = std::move(content);
    extracted_sig = std::move(sig);
    return 0;
}

/**
 * Extract the individual components of a given input container json.
 * @param nonce The extracted nonce.
 * @param input The extracted input.
 * @param max_ledger_seqno Themaxledgerseqno extracted max ledger sequence no.
 * @param contentjson The json string containing the input container message.
 *                    {
 *                      "nonce": "<random string with optional sorted order>",
 *                      "input": "<hex encoded contract input content>",
 *                      "max_ledger_seqno": <integer>
 *                    }
 * @return 0 on succesful extraction. -1 on failure.
 */
int extract_input_container(std::string &nonce, std::string &input, uint64_t &max_ledger_seqno, std::string_view contentjson)
{
    rapidjson::Document d;
    d.Parse(contentjson.data());
    if (d.HasParseError())
    {
        LOG_DBG << "User input container json parsing failed.";
        return -1;
    }

    if (!d.HasMember(FLD_NONCE) || !d.HasMember(FLD_INPUT) || !d.HasMember(FLD_MAX_LED_SEQ))
    {
        LOG_DBG << "User input container required fields missing.";
        return -1;
    }

    if (!d[FLD_NONCE].IsString() || !d[FLD_INPUT].IsString() || !d[FLD_MAX_LED_SEQ].IsUint64())
    {
        LOG_DBG << "User input container invaid field values.";
        return -1;
    }

    const rapidjson::Value &inputval = d[FLD_INPUT];
    std::string_view inputhex(inputval.GetString(), inputval.GetStringLength());

    // Convert hex input to binary.
    input.resize(inputhex.length() / 2);
    if (util::hex2bin(
            reinterpret_cast<unsigned char *>(input.data()),
            input.length(),
            inputhex) != 0)
    {
        LOG_DBG << "Contract input format invalid.";
        return -1;
    }

    nonce = d[FLD_NONCE].GetString();
    max_ledger_seqno = d[FLD_MAX_LED_SEQ].GetUint64();

    return 0;
}

/**
 * Parses a json message sent by a user.
 * @param d RapidJson document to which the parsed json should be loaded.
 * @param message The message to parse.
 *                Accepted message format:
 *                {
 *                  'type': '<message type>'
 *                  ...
 *                }
 * @return 0 on successful parsing. -1 for failure.
 */
int parse_user_message(rapidjson::Document &d, std::string_view message)
{
    // We load response raw bytes into json document.
    // Because we project the response message directly from the binary socket buffer in a zero-copy manner, the response
    // string is not null terminated. 'kParseStopWhenDoneFlag' avoids rapidjson error in this case.
    d.Parse<rapidjson::kParseStopWhenDoneFlag>(message.data());
    if (d.HasParseError())
    {
        LOG_DBG << "User json message parsing failed.";
        return -1;
    }

    // Check existence of msg type field.
    if (!d.HasMember(FLD_TYPE) || !d[FLD_TYPE].IsString())
    {
        LOG_DBG << "User json message 'type' missing or invalid.";
        return -1;
    }

    return 0;
}

} // namespace jsonschema::usrmsg