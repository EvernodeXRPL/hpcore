#include "../../pchheader.hpp"
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
    void create_status_response(std::vector<uint8_t> &msg)
    {
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
    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason, std::string_view input_sig)
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
    void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content)
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
    void create_contract_output_container(std::vector<uint8_t> &msg, std::string_view content)
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
    int parse_user_message(jsoncons::ojson &d, std::string_view message)
    {
        return 0;
    }

    /**
 * Extracts the message 'type' value from the bson document.
 */
    int extract_type(std::string &extracted_type, const jsoncons::ojson &d)
    {
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
    int extract_read_request(std::string &extracted_content, jsoncons::ojson &d)
    {
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
        std::string &extracted_input_container, std::string &extracted_sig, jsoncons::ojson &d)
    {
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
        return 0;
    }

} // namespace msg::usrmsg::bson