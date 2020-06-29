#include "../../pchheader.hpp"
#include "microbson.hpp"
#include "minibson.hpp"
#include "../../util.hpp"
#include "../../cons/cons.hpp"
#include "../../hplog.hpp"
#include "../usrmsg_common.hpp"
#include "usrmsg_bson.hpp"

namespace msg::usrmsg::bson
{
    /**
 * Constructs a status response message.
 * @param msg String reference to copy the generated bson message into.
 *            Message format:
 *            {
 *              "type": "stat_response",
 *              "lcl": "<lcl id>",
 *              "lcl_seqno": <integer>
 *            }
 */
    void create_status_response(std::string &msg)
    {
        minibson::document d;
        d.set(FLD_TYPE, msg::usrmsg::MSGTYPE_STAT_RESPONSE);
        d.set(FLD_LCL, cons::ctx.lcl);
        d.set(FLD_LCL_SEQ, cons::ctx.led_seq_no);

        msg.resize(d.get_serialized_size());
        d.serialize(msg.data(), msg.size());
    }

    /**
 * Constructs a contract input status message.
 * @param msg String reference to copy the generated bson message into.
 *            Message format:
 *            {
 *              "type": "contract_input_status",
 *              "status": "<accepted|rejected>",
 *              "reason": "<reson>",
 *              "input_sig": <signature of original input message>
 *            }
 * @param is_accepted Whether the original message was accepted or not.
 * @param reason Rejected reason. Empty if accepted.
 * @param input_sig Binary signature of the original input message which generated this result.
 */
    void create_contract_input_status(std::string &msg, std::string_view status, std::string_view reason, std::string_view input_sig)
    {
    }

    /**
 * Constructs a contract read response message.
 * @param msg String reference to copy the generated bson message into.
 *            Message format:
 *            {
 *              "type": "contract_read_response",
 *              "content": <contract output>
 *            }
 * @param content The contract binary output content to be put in the message.
 */
    void create_contract_read_response_container(std::string &msg, std::string_view content)
    {
    }

    /**
 * Constructs a contract output container message.
 * @param msg String reference to copy the generated bson message into.
 *            Message format:
 *            {
 *              "type": "contract_output",
 *              "lcl": "<lcl id>"
 *              "lcl_seqno": <integer>,
 *              "content": <contract output>
 *            }
 * @param content The contract binary output content to be put in the message.
 */
    void create_contract_output_container(std::string &msg, std::string_view content)
    {
    }

    /**
 * Parses a bson message sent by a user.
 * @param d BSON document to which the parsed bson should be loaded.
 * @param message The message to parse.
 *                Accepted message format:
 *                {
 *                  'type': '<message type>'
 *                  ...
 *                }
 * @return 0 on successful parsing. -1 for failure.
 */
    int parse_user_message(microbson::document &d, std::string_view message)
    {
        d.load((void *)message.data(), message.size());

        if (!d.valid())
        {
            LOG_DBG << "User bson message parsing failed.";
            return -1;
        }

        // Check existence of msg type field.
        if (!d.contains<std::string>(msg::usrmsg::FLD_TYPE))
        {
            LOG_DBG << "User bson message 'type' missing or invalid.";
            return -1;
        }

        return 0;
    }

    /**
 * Extracts the message 'type' value from the bson document.
 */
    int extract_type(std::string &extracted_type, const microbson::document &d)
    {
        extracted_type = d.get(msg::usrmsg::FLD_TYPE, "");
        return 0;
    }

    /**
 * Extracts a contract read request message sent by user.
 * 
 * @param extracted_content The content to be passed to the contract, extracted from the message.
* @param d The bson document holding the read request message.
 *          Accepted signed input container format:
 *          {
 *            "type": "contract_read_request",
 *            "content": <content to be passed to the contract>
 *          }
 * @return 0 on successful extraction. -1 for failure.
 */
    int extract_read_request(std::string &extracted_content, microbson::document &d)
    {
        if (!d.contains<void *>(msg::usrmsg::FLD_CONTENT))
        {
            LOG_DBG << "Read request content field missing or invalid.";
            return -1;
        }

        std::pair<void *, size_t> buf = d.get(FLD_CONTENT);
        extracted_content = std::string_view(reinterpret_cast<char *>(buf.first), buf.second);
        return 0;
    }

    /**
 * Extracts a signed input container message sent by user.
 * 
 * @param extracted_input_container The input container extracted from the message.
 * @param extracted_sig The binary signature extracted from the message. 
 * @param d The bson document holding the input container.
 *          Accepted signed input container format:
 *          {
 *            "type": "contract_input",
 *            "input_container": <bson input container message>,
 *            "sig": <signature of the content>
 *          }
 * @return 0 on successful extraction. -1 for failure.
 */
    int extract_signed_input_container(
        std::string &extracted_input_container, std::string &extracted_sig, microbson::document &d)
    {
        if (!d.contains<microbson::document>(msg::usrmsg::FLD_INPUT_CONTAINER) || !d.contains<void *>(msg::usrmsg::FLD_SIG))
        {
            LOG_DBG << "User signed input required fields missing or invalid.";
            return -1;
        }

        // We do not verify the signature of the content here since we need to let each node
        // (including self) to verify that individually after we broadcast the NUP proposal.

        std::pair<void *, size_t> buf1 = d.get(FLD_INPUT_CONTAINER);
        extracted_input_container = std::string_view(reinterpret_cast<char *>(buf1.first), buf1.second);

        std::pair<void *, size_t> buf2 = d.get(FLD_SIG);
        extracted_sig = std::string_view(reinterpret_cast<char *>(buf2.first), buf2.second);

        return 0;
    }

    /**
 * Extract the individual components of a given input container bson.
 * @param input The extracted input.
 * @param nonce The extracted nonce.
 * @param max_lcl_seqno The extracted max ledger sequence no.
 * @param contentjson The bson input container message.
 *                    {
 *                      "input": <contract input content>,
 *                      "nonce": "<random string with optional sorted order>",
 *                      "max_lcl_seqno": <integer>
 *                    }
 * @return 0 on succesful extraction. -1 on failure.
 */
    int extract_input_container(std::string &input, std::string &nonce, uint64_t &max_lcl_seqno, std::string_view contentbson)
    {
        microbson::document d((void *)contentbson.data(), contentbson.size());
        if (!d.valid())
        {
            LOG_DBG << "User input container bson parsing failed.";
            return -1;
        }

        if (!d.contains<std::string>(msg::usrmsg::FLD_NONCE) || !d.contains<void *>(msg::usrmsg::FLD_INPUT) || !d.contains<uint64_t>(msg::usrmsg::FLD_MAX_LCL_SEQ))
        {
            LOG_DBG << "User input container required fields missing.";
            return -1;
        }

        std::pair<void *, size_t> buf = d.get(FLD_INPUT);
        input = std::string_view(reinterpret_cast<char *>(buf.first), buf.second);
        nonce = d.get(msg::usrmsg::FLD_NONCE, "");
        max_lcl_seqno = d.get(msg::usrmsg::FLD_MAX_LCL_SEQ, "");

        return 0;
    }

} // namespace msg::usrmsg::bson