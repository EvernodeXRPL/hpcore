#include "../../pchheader.hpp"
#include "../../util.hpp"
#include "../../crypto.hpp"
#include "../../cons/cons.hpp"
#include "../../hplog.hpp"
#include "../usrmsg_common.hpp"
#include "usrmsg_json.hpp"

namespace common = msg::usrmsg_common;

namespace msg::usrmsg::json
{
    // JSON separators
    constexpr const char *SEP_COMMA = "\",\"";
    constexpr const char *SEP_COLON = "\":\"";
    constexpr const char *SEP_COMMA_NOQUOTE = ",\"";
    constexpr const char *SEP_COLON_NOQUOTE = "\":";

    /**
 * Constructs user challenge message json and the challenge string required for
 * initial user challenge handshake. This gets called when a user establishes
 * a web socket connection to HP.
 * 
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "type": "handshake_challenge",
 *              "challenge": "<hex challenge string>"
 *            }
 * @param challengehex String reference to copy the generated hex challenge string into.
 */
    void create_user_challenge(std::string &msg, std::string &challengehex)
    {
        // Use libsodium to generate the random challenge bytes.
        unsigned char challenge_bytes[common::CHALLENGE_LEN];
        randombytes_buf(challenge_bytes, common::CHALLENGE_LEN);

        // We pass the hex challenge string separately to the caller even though
        // we also include it in the challenge msg as well.

        util::bin2hex(challengehex, challenge_bytes, common::CHALLENGE_LEN);

        // Construct the challenge msg json.
        // We do not use RapidJson here in favour of performance because this is a simple json message.

        // Since we know the rough size of the challenge message we reserve adequate amount for the holder.
        // Only Hot Pocket version number is variable length. Therefore message size is roughly 90 bytes
        // so allocating 128bytes for heap padding.
        msg.reserve(128);
        msg.append("{\"")
            .append(common::FLD_TYPE)
            .append(SEP_COLON)
            .append(common::MSGTYPE_HANDSHAKE_CHALLENGE)
            .append(SEP_COMMA)
            .append(common::FLD_CHALLENGE)
            .append(SEP_COLON)
            .append(challengehex)
            .append("\"}");
    }

    /**
 * Constructs a status response message.
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "type": "stat_response",
 *              "lcl": "<lcl id>",
 *              "lcl_seqno": <integer>
 *            }
 */
    void create_status_response(std::string &msg)
    {
        msg.reserve(128);
        msg.append("{\"")
            .append(common::FLD_TYPE)
            .append(SEP_COLON)
            .append(common::MSGTYPE_STAT_RESPONSE)
            .append(SEP_COMMA)
            .append(common::FLD_LCL)
            .append(SEP_COLON)
            .append(cons::ctx.lcl)
            .append(SEP_COMMA)
            .append(common::FLD_LCL_SEQ)
            .append(SEP_COLON_NOQUOTE)
            .append(std::to_string(cons::ctx.led_seq_no))
            .append("}");
    }

    /**
 * Constructs a contract input status message.
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "type": "contract_input_status",
 *              "status": "<accepted|rejected>",
 *              "reason": "<reson>",
 *              "input_sig": "<hex sig of original input message>"
 *            }
 * @param is_accepted Whether the original message was accepted or not.
 * @param reason Rejected reason. Empty if accepted.
 * @param input_sig Binary signature of the original input message which generated this result.
 */
    void create_contract_input_status(std::string &msg, std::string_view status, std::string_view reason, std::string_view input_sig)
    {
        std::string sighex;
        util::bin2hex(sighex, reinterpret_cast<const unsigned char *>(input_sig.data()), input_sig.length());

        msg.reserve(128);
        msg.append("{\"")
            .append(common::FLD_TYPE)
            .append(SEP_COLON)
            .append(common::MSGTYPE_CONTRACT_INPUT_STATUS)
            .append(SEP_COMMA)
            .append(common::FLD_STATUS)
            .append(SEP_COLON)
            .append(status)
            .append(SEP_COMMA)
            .append(common::FLD_REASON)
            .append(SEP_COLON)
            .append(reason)
            .append(SEP_COMMA)
            .append(common::FLD_INPUT_SIG)
            .append(SEP_COLON)
            .append(sighex)
            .append("\"}");
    }

    /**
 * Constructs a contract read response message.
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "type": "contract_read_response",
 *              "content": "<hex encoded contract output>"
 *            }
 * @param content The contract binary output content to be put in the message.
 */
    void create_contract_read_response_container(std::string &msg, std::string_view content)
    {
        std::string contenthex;
        util::bin2hex(
            contenthex,
            reinterpret_cast<const unsigned char *>(content.data()),
            content.length());

        msg.reserve(256);
        msg.append("{\"")
            .append(common::FLD_TYPE)
            .append(SEP_COLON)
            .append(common::MSGTYPE_CONTRACT_READ_RESPONSE)
            .append(SEP_COMMA)
            .append(common::FLD_CONTENT)
            .append(SEP_COLON)
            .append(contenthex)
            .append("\"}");
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
            .append(common::FLD_TYPE)
            .append(SEP_COLON)
            .append(common::MSGTYPE_CONTRACT_OUTPUT)
            .append(SEP_COMMA)
            .append(common::FLD_LCL)
            .append(SEP_COLON)
            .append(cons::ctx.lcl)
            .append(SEP_COMMA)
            .append(common::FLD_LCL_SEQ)
            .append(SEP_COLON_NOQUOTE)
            .append(std::to_string(cons::ctx.led_seq_no))
            .append(SEP_COMMA_NOQUOTE)
            .append(common::FLD_CONTENT)
            .append(SEP_COLON)
            .append(contenthex)
            .append("\"}");
    }

    /**
 * Verifies the user handshake response with the original challenge issued to the user
 * and the user public key contained in the response.
 * 
 * @param extracted_pubkeyhex The hex public key extracted from the response.
 * @param extracted_protocol The protocol code extracted from the response.
 * @param response The response bytes to verify. This will be parsed as json.
 *                 Accepted response format:
 *                 {
 *                   "type": "handshake_response",
 *                   "challenge": "<original hex challenge the user received>",
 *                   "sig": "<hex signature of the challenge>",
 *                   "pubkey": "<hex public key of the user>",
 *                   "protocol": "<json | bson>"
 *                 }
 * @param original_challenge The original hex challenge string issued to the user.
 * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
 */
    int verify_user_handshake_response(std::string &extracted_pubkeyhex, std::string &extracted_protocol,
                                       std::string_view response, std::string_view original_challenge)
    {
        rapidjson::Document d;
        if (parse_user_message(d, response) != 0)
            return -1;

        // Validate msg type.
        if (d[common::FLD_TYPE] != common::MSGTYPE_HANDSHAKE_RESPONSE)
        {
            LOG_DBG << "User handshake response type invalid. 'handshake_response' expected.";
            return -1;
        }

        // Compare the response handshake string with the original issued challenge.
        if (!d.HasMember(common::FLD_CHALLENGE) || d[common::FLD_CHALLENGE] != original_challenge.data())
        {
            LOG_DBG << "User handshake response 'challenge' invalid.";
            return -1;
        }

        // Check for the 'sig' field existence.
        if (!d.HasMember(common::FLD_SIG) || !d[common::FLD_SIG].IsString())
        {
            LOG_DBG << "User handshake response 'challenge signature' invalid.";
            return -1;
        }

        // Check for the 'pubkey' field existence.
        if (!d.HasMember(common::FLD_PUBKEY) || !d[common::FLD_PUBKEY].IsString())
        {
            LOG_DBG << "User handshake response 'public key' invalid.";
            return -1;
        }

        // Check for protocol field existence and valid value.
        if (!d.HasMember(common::FLD_PROTOCOL) || !d[common::FLD_PROTOCOL].IsString())
        {

            LOG_DBG << "User handshake response 'protocol' invalid.";
            return -1;
        }

        std::string_view protocolsv = util::getsv(d[common::FLD_PROTOCOL]);
        if (protocolsv != "json" && protocolsv != "bson")
        {
            LOG_DBG << "User handshake response 'protocol' type invalid.";
            return -1;
        }

        // Verify the challenge signature. We do this last due to signature verification cost.
        std::string_view pubkeysv = util::getsv(d[common::FLD_PUBKEY]);
        if (crypto::verify_hex(
                original_challenge,
                util::getsv(d[common::FLD_SIG]),
                pubkeysv) != 0)
        {
            LOG_DBG << "User challenge response signature verification failed.";
            return -1;
        }

        extracted_pubkeyhex = pubkeysv;
        extracted_protocol = protocolsv;

        return 0;
    }

    /**
 * Extracts a contract read request message sent by user.
 * 
 * @param extracted_content The content to be passed to the contract, extracted from the message.
* @param d The json document holding the read request message.
 *          Accepted signed input container format:
 *          {
 *            "type": "contract_read_request",
 *            "content": "<hex encoded content to be passed to the contract>"
 *          }
 * @return 0 on successful extraction. -1 for failure.
 */
    int extract_read_request(std::string &extracted_content, const rapidjson::Document &d)
    {
        if (!d.HasMember(common::FLD_CONTENT))
        {
            LOG_DBG << "Read request required fields missing.";
            return -1;
        }

        if (!d[common::FLD_CONTENT].IsString())
        {
            LOG_DBG << "Read request invalid field values.";
            return -1;
        }

        std::string_view contenthex(d[common::FLD_CONTENT].GetString(), d[common::FLD_CONTENT].GetStringLength());

        std::string content;
        content.resize(contenthex.length() / 2);
        if (util::hex2bin(
                reinterpret_cast<unsigned char *>(content.data()),
                content.length(),
                contenthex) != 0)
        {
            LOG_DBG << "Read request format invalid.";
            return -1;
        }

        extracted_content = std::move(content);
        return 0;
    }

    /**
 * Extracts a signed input container message sent by user.
 * 
 * @param extracted_input_container The input container extracted from the message.
 * @param extracted_sig The binary signature extracted from the message. 
 * @param d The json document holding the input container.
 *          Accepted signed input container format:
 *          {
 *            "type": "contract_input",
 *            "input_container": "<stringified json input container message>",
 *            "sig": "<hex encoded signature of the content>"
 *          }
 * @return 0 on successful extraction. -1 for failure.
 */
    int extract_signed_input_container(
        std::string &extracted_input_container, std::string &extracted_sig, const rapidjson::Document &d)
    {
        if (!d.HasMember(common::FLD_INPUT_CONTAINER) || !d.HasMember(common::FLD_SIG))
        {
            LOG_DBG << "User signed input required fields missing.";
            return -1;
        }

        if (!d[common::FLD_INPUT_CONTAINER].IsString() || !d[common::FLD_SIG].IsString())
        {
            LOG_DBG << "User signed input invalid field values.";
            return -1;
        }

        // We do not verify the signature of the content here since we need to let each node
        // (including self) to verify that individually after we broadcast the NUP proposal.

        const std::string input_container(d[common::FLD_INPUT_CONTAINER].GetString(), d[common::FLD_INPUT_CONTAINER].GetStringLength());

        const std::string_view sighex(d[common::FLD_SIG].GetString(), d[common::FLD_SIG].GetStringLength());
        std::string sig;
        sig.resize(crypto_sign_ed25519_BYTES);
        util::hex2bin(reinterpret_cast<unsigned char *>(sig.data()), sig.length(), sighex);

        extracted_input_container = std::move(input_container);
        extracted_sig = std::move(sig);
        return 0;
    }

    /**
 * Extract the individual components of a given input container json.
 * @param input The extracted input.
 * @param nonce The extracted nonce.
 * @param max_lcl_seqno The extracted max ledger sequence no.
 * @param contentjson The json string containing the input container message.
 *                    {
 *                      "input": "<hex encoded contract input content>",
 *                      "nonce": "<random string with optional sorted order>",
 *                      "max_lcl_seqno": <integer>
 *                    }
 * @return 0 on succesful extraction. -1 on failure.
 */
    int extract_input_container(std::string &input, std::string &nonce, uint64_t &max_lcl_seqno, std::string_view contentjson)
    {
        rapidjson::Document d;
        d.Parse(contentjson.data());
        if (d.HasParseError())
        {
            LOG_DBG << "User input container json parsing failed.";
            return -1;
        }

        if (!d.HasMember(common::FLD_NONCE) || !d.HasMember(common::FLD_INPUT) || !d.HasMember(common::FLD_MAX_LCL_SEQ))
        {
            LOG_DBG << "User input container required fields missing.";
            return -1;
        }

        if (!d[common::FLD_NONCE].IsString() || !d[common::FLD_INPUT].IsString() || !d[common::FLD_MAX_LCL_SEQ].IsUint64())
        {
            LOG_DBG << "User input container invalid field values.";
            return -1;
        }

        const rapidjson::Value &inputval = d[common::FLD_INPUT];
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

        nonce = d[common::FLD_NONCE].GetString();
        max_lcl_seqno = d[common::FLD_MAX_LCL_SEQ].GetUint64();

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
        if (!d.HasMember(common::FLD_TYPE) || !d[common::FLD_TYPE].IsString())
        {
            LOG_DBG << "User json message 'type' missing or invalid.";
            return -1;
        }

        return 0;
    }

} // namespace msg::usrmsg::json