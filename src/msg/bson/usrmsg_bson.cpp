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
      jsoncons::bson::bson_bytes_encoder encoder(msg);
      encoder.begin_object();
      encoder.key(msg::usrmsg::FLD_TYPE);
      encoder.string_value(msg::usrmsg::MSGTYPE_STAT_RESPONSE);
      encoder.key(msg::usrmsg::FLD_LCL);
      encoder.string_value(cons::ctx.lcl);
      encoder.key(msg::usrmsg::FLD_LCL_SEQ);
      encoder.int64_value(cons::ctx.led_seq_no);
      encoder.end_object();
      encoder.flush();
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
      jsoncons::bson::bson_bytes_encoder encoder(msg);
      encoder.begin_object();
      encoder.key(msg::usrmsg::FLD_TYPE);
      encoder.string_value(msg::usrmsg::MSGTYPE_CONTRACT_INPUT_STATUS);
      encoder.key(msg::usrmsg::FLD_STATUS);
      encoder.string_value(status);
      encoder.key(msg::usrmsg::FLD_REASON);
      encoder.string_value(reason);
      encoder.key(msg::usrmsg::FLD_INPUT_SIG);
      encoder.byte_string_value(input_sig);
      encoder.end_object();
      encoder.flush();
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
      jsoncons::bson::bson_bytes_encoder encoder(msg);
      encoder.begin_object();
      encoder.key(msg::usrmsg::FLD_TYPE);
      encoder.string_value(msg::usrmsg::MSGTYPE_CONTRACT_READ_RESPONSE);
      encoder.key(msg::usrmsg::FLD_CONTENT);
      encoder.byte_string_value(content);
      encoder.end_object();
      encoder.flush();
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
      jsoncons::bson::bson_bytes_encoder encoder(msg);
      encoder.begin_object();
      encoder.key(msg::usrmsg::FLD_TYPE);
      encoder.string_value(msg::usrmsg::MSGTYPE_CONTRACT_OUTPUT);
      encoder.key(msg::usrmsg::FLD_LCL);
      encoder.string_value(cons::ctx.lcl);
      encoder.key(msg::usrmsg::FLD_LCL_SEQ);
      encoder.int64_value(cons::ctx.led_seq_no);
      encoder.key(msg::usrmsg::FLD_CONTENT);
      encoder.byte_string_value(content);
      encoder.end_object();
      encoder.flush();
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
      try
      {
         d = jsoncons::bson::decode_bson<jsoncons::ojson>(message);
      }
      catch (const std::exception &e)
      {
         LOG_DBG << "User bson message parsing failed.";
         return -1;
      }

      if (!d[FLD_TYPE].is_string())
      {
         LOG_DBG << "User bson message 'type' missing or invalid.";
         return -1;
      }

      return 0;
   }

   /**
 * Extracts the message 'type' value from the bson document.
 */
   int extract_type(std::string &extracted_type, const jsoncons::ojson &d)
   {
      extracted_type = d[FLD_TYPE].as<std::string>();
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
   int extract_read_request(std::string &extracted_content, const jsoncons::ojson &d)
   {
      if (!d[msg::usrmsg::FLD_CONTENT].is_byte_string_view())
      {
         LOG_DBG << "Read request 'content' fields missing or invalid.";
         return -1;
      }

      const jsoncons::byte_string_view &bsv = d[msg::usrmsg::FLD_CONTENT].as_byte_string_view();
      extracted_content = std::string_view(reinterpret_cast<const char *>(bsv.data()), bsv.size());
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
       std::string &extracted_input_container, std::string &extracted_sig, const jsoncons::ojson &d)
   {
      if (!d[msg::usrmsg::FLD_INPUT_CONTAINER].is_byte_string_view() || !d[msg::usrmsg::FLD_SIG].is_byte_string_view())
      {
         LOG_DBG << "User signed input required fields missing or invalid.";
         return -1;
      }

      const jsoncons::byte_string_view &bsv1 = d[msg::usrmsg::FLD_INPUT_CONTAINER].as_byte_string_view();
      extracted_input_container = std::string_view(reinterpret_cast<const char *>(bsv1.data()), bsv1.size());

      const jsoncons::byte_string_view &bsv2 = d[msg::usrmsg::FLD_SIG].as_byte_string_view();
      extracted_sig = std::string_view(reinterpret_cast<const char *>(bsv2.data()), bsv2.size());

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
      jsoncons::ojson d;
      try
      {
         d = jsoncons::bson::decode_bson<jsoncons::ojson>(contentbson);
      }
      catch (const std::exception &e)
      {
         LOG_DBG << "User input container bson parsing failed.";
         return -1;
      }

      if (!d[msg::usrmsg::FLD_INPUT].is_byte_string_view() || !d[msg::usrmsg::FLD_NONCE].is_string() || !d[msg::usrmsg::FLD_MAX_LCL_SEQ].is_uint64())
      {
         LOG_DBG << "User input container required fields missing or invalid.";
         return -1;
      }

      const jsoncons::byte_string_view &bsv = d[msg::usrmsg::FLD_INPUT].as_byte_string_view();
      input = std::string_view(reinterpret_cast<const char *>(bsv.data()), bsv.size());

      nonce = d[msg::usrmsg::FLD_NONCE].as<std::string>();
      max_lcl_seqno = d[msg::usrmsg::FLD_MAX_LCL_SEQ].as<uint64_t>();
      return 0;
   }

} // namespace msg::usrmsg::bson