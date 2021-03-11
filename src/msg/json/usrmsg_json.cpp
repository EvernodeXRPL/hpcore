#include "../../pchheader.hpp"
#include "../../util/util.hpp"
#include "../../util/merkle_hash_tree.hpp"
#include "../../unl.hpp"
#include "../../crypto.hpp"
#include "../../hplog.hpp"
#include "../../conf.hpp"
#include "../usrmsg_common.hpp"
#include "usrmsg_json.hpp"

namespace msg::usrmsg::json
{
    // JSON separators
    constexpr const char *SEP_COMMA = "\",\"";
    constexpr const char *SEP_COLON = "\":\"";
    constexpr const char *SEP_COMMA_NOQUOTE = ",\"";
    constexpr const char *SEP_COLON_NOQUOTE = "\":";
    constexpr const char *DOUBLE_QUOTE = "\"";
    constexpr const char *OPEN_SQR_BRACKET = "[";
    constexpr const char *CLOSE_SQR_BRACKET = "]";

    constexpr const size_t MAX_KNOWN_PEERS_INFO = 10;

    // std::vector overload to concatonate string.
    std::vector<uint8_t> &operator+=(std::vector<uint8_t> &vec, std::string_view sv)
    {
        vec.insert(vec.end(), sv.begin(), sv.end());
        return vec;
    }

    /**
     * Constructs user challenge message json and the challenge string required for
     * initial user challenge handshake. This gets called when a user establishes
     * a web socket connection to HP.
     * 
     * @param msg String reference to copy the generated json message string into.
     *            Message format:
     *            {
     *              "hp_version": "<hp protocol version>",
     *              "type": "user_challenge",
     *              "contract_id": "<contract id>",
     *              "contract_version": "<contract version string>",
     *              "challenge": "<challenge string>"
     *            }
     * @param challenge_bytes String reference to copy the generated challenge bytes into.
     */
    void create_user_challenge(std::vector<uint8_t> &msg, std::string &challenge)
    {
        std::string challenge_bytes;
        crypto::random_bytes(challenge_bytes, msg::usrmsg::CHALLENGE_LEN);
        challenge = util::to_hex(challenge_bytes);

        // Construct the challenge msg json.
        // We do not use jsoncons library here in favour of performance because this is a simple json message.

        // Since we know the rough size of the challenge message we reserve adequate amount for the holder.
        // Only Hot Pocket version number is variable length.
        msg.reserve(256);
        msg += "{\"";
        msg += msg::usrmsg::FLD_HP_VERSION;
        msg += SEP_COLON;
        msg += conf::cfg.hp_version;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_USER_CHALLENGE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_CONTRACT_ID;
        msg += SEP_COLON;
        msg += conf::cfg.contract.id;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_CONTRACT_VERSION;
        msg += SEP_COLON;
        msg += conf::cfg.contract.version;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_CHALLENGE;
        msg += SEP_COLON;
        msg += challenge;
        msg += "\"}";
    }

    /**
     * Constructs server challenge response message json. This gets sent when we receive
     * a challenge from the user.
     * 
     * @param msg String reference to copy the generated json message string into.
     *            Message format:
     *            {
     *              "type": "server_challenge_response",
     *              "sig": "<hex encoded signature of the [challenge + contract_id]>",
     *              "pubkey": "<our public key in hex>",
     *              "unl": [<hex unl pubkey list>]
     *            }
     * @param original_challenge Original challenge issued by the user.
     */
    void create_server_challenge_response(std::vector<uint8_t> &msg, const std::string &original_challenge)
    {
        // Generate signature of challenge + contract id + contract version.
        const std::string content = original_challenge + conf::cfg.contract.id + conf::cfg.contract.version;
        const std::string sig_hex = util::to_hex(crypto::sign(content, conf::cfg.node.private_key));

        // Since we know the rough size of the challenge message we reserve adequate amount for the holder.
        msg.reserve(1024);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_SERVER_CHALLENGE_RESPONSE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_SIG;
        msg += SEP_COLON;
        msg += sig_hex;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_PUBKEY;
        msg += SEP_COLON;
        msg += conf::cfg.node.public_key_hex;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_UNL;
        msg += "\":[";
        const std::set<std::string> unl_list = unl::get();
        for (auto itr = unl_list.begin(); itr != unl_list.end(); itr++)
        {
            msg += "\"";
            msg += util::to_hex(*itr);
            msg += "\"";
            if (std::next(itr) != unl_list.end())
                msg += ",";
        }
        msg += "]}";
    }

    /**
     * Constructs a status response message.
     * @param msg String reference to copy the generated json message string into.
     *            Message format:
     *            {
     *              "type": "stat_response",
     *              "lcl_seq_no": <lcl sequence no>,
     *              "lcl_hash": "<lcl hash hex>"
     *            }
     */
    void create_status_response(std::vector<uint8_t> &msg, const uint64_t lcl_seq_no, std::string_view lcl_hash)
    {
        const uint16_t msg_length = 406 + (69 * conf::cfg.contract.unl.size());

        msg.reserve(msg_length);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_STAT_RESPONSE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_HP_VERSION;
        msg += SEP_COLON;
        msg += conf::cfg.hp_version;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_LCL_SEQ;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(lcl_seq_no);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_LCL_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(lcl_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_ROUND_TIME;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(conf::cfg.contract.roundtime); 
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_CONTARCT_EXECUTION_ENABLED;
        msg += SEP_COLON_NOQUOTE;
        msg += conf::cfg.contract.execute ? "true" : "false";  
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_READ_REQUESTS_ENABLED;
        msg += SEP_COLON_NOQUOTE;
        msg += conf::cfg.user.concurrent_read_reqeuests != 0 ? "true" : "false"; 
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_IS_FULL_HISTORY_NODE;
        msg += SEP_COLON_NOQUOTE;
        msg += conf::cfg.node.history == conf::HISTORY::FULL ? "true" : "false";
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_CURRENT_UNL;
        msg += SEP_COLON_NOQUOTE;
        msg += OPEN_SQR_BRACKET;

        for (auto node = conf::cfg.contract.unl.begin(); node != conf::cfg.contract.unl.end(); node++)
        {
            msg += DOUBLE_QUOTE + util::to_hex(*node) + DOUBLE_QUOTE;

            if (std::next(node) != conf::cfg.contract.unl.end())
                msg += ",";
        }

        msg += CLOSE_SQR_BRACKET;
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_PEERS;
        msg += SEP_COLON_NOQUOTE;
        msg += OPEN_SQR_BRACKET;

        {
            std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

            const size_t max_peers_count = MIN(MAX_KNOWN_PEERS_INFO, p2p::ctx.peer_connections.size());
            size_t count = 1;

            // Currently all peers, up to a max of 10 are sent regardless of state.
            for (auto peer = p2p::ctx.peer_connections.begin(); peer != p2p::ctx.peer_connections.end() && count <= max_peers_count; peer++, count++)
            {
                msg += DOUBLE_QUOTE + peer->second->known_ipport->host_address + ":" + std::to_string(peer->second->known_ipport->port) + DOUBLE_QUOTE;

                if (peer != p2p::ctx.peer_connections.end() && count < max_peers_count)
                    msg += ",";
            }
        }

        msg += CLOSE_SQR_BRACKET;
        msg += "}";
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
    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason, std::string_view input_sig)
    {
        msg.reserve(256);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_CONTRACT_INPUT_STATUS;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_STATUS;
        msg += SEP_COLON;
        msg += status;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_REASON;
        msg += SEP_COLON;
        msg += reason;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_INPUT_SIG;
        msg += SEP_COLON;
        msg += util::to_hex(input_sig);
        msg += "\"}";
    }

    /**
     * Constructs a contract read response message.
     * @param msg String reference to copy the generated json message string into.
     *            Message format:
     *            {
     *              "type": "contract_read_response",
     *              "content": "<response string>"
     *            }
     * @param content The contract binary output content to be put in the message.
     */
    void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content)
    {
        msg.reserve(content.size() + 256);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_CONTRACT_READ_RESPONSE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_CONTENT;
        msg += SEP_COLON_NOQUOTE;

        if (is_json_string(content))
        {
            // Process the final string using jsoncons.
            jsoncons::json jstring = content;
            jsoncons::json_options options;
            options.escape_all_non_ascii(true);

            std::string escaped_content;
            jstring.dump(escaped_content);

            msg += escaped_content;
        }
        else
        {
            msg += content;
        }

        msg += "}";
    }

    /**
     * Constructs a contract output container message.
     * @param msg String reference to copy the generated json message string into.
     *            Message format:
     *            {
     *              "type": "contract_output",
     *              "lcl_seq_no": <integer>,
     *              "lcl_hash": "<lcl hash hex>",
     *              "outputs": ["<output string 1>", "<output string 2>", ...], // The output order is the hash order.
     *              "hashes": [<hex merkle hash tree>], // Always includes user's output hash [output hash = hash(pubkey+all outputs for the user)]
     *              "unl_sig": [["<pubkey hex>", "<sig hex>"], ...] // UNL pubkeys and signatures of root hash.
     *            }
     * @param content The contract binary output content to be put in the message.
     */
    void create_contract_output_container(std::vector<uint8_t> &msg, const ::std::vector<std::string_view> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash)
    {
        msg.reserve(1024);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_CONTRACT_OUTPUT;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_LCL_SEQ;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(lcl_seq_no);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_LCL_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(lcl_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_OUTPUTS;
        msg += "\":[";

        for (int i = 0; i < outputs.size(); i++)
        {
            std::string_view output = outputs[i];

            if (is_json_string(output))
            {
                // Process the final string using jsoncons.
                jsoncons::json jstring = output;
                jsoncons::json_options options;
                options.escape_all_non_ascii(true);

                std::string escaped_content;
                jstring.dump(escaped_content);

                msg += escaped_content;
            }
            else
            {
                msg += output;
            }

            if (i < outputs.size() - 1)
                msg += ",";
        }

        msg += "],\"";

        msg += msg::usrmsg::FLD_HASHES;
        msg += "\":";
        populate_output_hash_array(msg, hash_root);
        msg += ",\"";

        msg += msg::usrmsg::FLD_UNL_SIG;
        msg += "\":[";
        for (int i = 0; i < unl_sig.size(); i++)
        {
            const auto &sig = unl_sig[i]; // Pubkey and Signature pair.
            msg += "[\"";
            msg += util::to_hex(sig.first);
            msg += "\",\"";
            msg += util::to_hex(sig.second);
            msg += "\"]";

            if (i < unl_sig.size() - 1)
                msg += ",";
        }
        msg += "]}";
    }

    /**
     * Constructs unl list container message.
     * @param msg String reference to copy the generated json message string into.
     *            Message format:
     *            {
     *              "type": "unl_change",
     *              "unl": ["<pubkey1>{[ed prefix][64 characters]}", ...] // Hex pubkey list of unl nodes.
     *            }
     * @param unl_list The unl node pubkey list to be put in the message.
     */
    void create_unl_list_container(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list)
    {
        msg.reserve((69 * unl_list.size()) + 30);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_UNL_CHANGE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_UNL;
        msg += "\":[";

        int i = 0;
        for (std::string_view unl : unl_list)
        {
            msg += DOUBLE_QUOTE;
            msg += util::to_hex(unl);
            msg += DOUBLE_QUOTE;
            if (i < unl_list.size() - 1)
                msg += ",";
            i++;
        }

        msg += "]}";
    }

    /**
     * Verifies the user handshake response with the original challenge issued to the user
     * and the user public key contained in the response.
     * 
     * @param extracted_pubkeyhex The hex public key extracted from the response.
     * @param extracted_protocol The protocol code extracted from the response.
     * @param extracted_server_challenge Any server challenge issued by user.
     * @param response The response bytes to verify. This will be parsed as json.
     *                 Accepted response format:
     *                 {
     *                   "type": "user_challenge_response",
     *                   "sig": "<hex signature of the challenge>",
     *                   "pubkey": "<hex public key of the user>",
     *                   "server_challenge": "<hex encoded challenge issued to server>", (max 16 bytes/32 chars)
     *                   "protocol": "<json | bson>"
     *                 }
     * @param original_challenge The original challenge string we issued to the user.
     * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
     */
    int verify_user_challenge(std::string &extracted_pubkeyhex, std::string &extracted_protocol, std::string &extracted_server_challenge,
                              std::string_view response, std::string_view original_challenge)
    {
        jsoncons::json d;
        if (parse_user_message(d, response) != 0)
            return -1;

        // Validate msg type.
        if (d[msg::usrmsg::FLD_TYPE] != msg::usrmsg::MSGTYPE_USER_CHALLENGE_RESPONSE)
        {
            LOG_DEBUG << "User challenge response type invalid. 'handshake_response' expected.";
            return -1;
        }

        // Check for the 'sig' field existence.
        if (!d.contains(msg::usrmsg::FLD_SIG) || !d[msg::usrmsg::FLD_SIG].is<std::string>())
        {
            LOG_DEBUG << "User challenge response 'challenge signature' invalid.";
            return -1;
        }

        // Check for the 'pubkey' field existence.
        if (!d.contains(msg::usrmsg::FLD_PUBKEY) || !d[msg::usrmsg::FLD_PUBKEY].is<std::string>())
        {
            LOG_DEBUG << "User challenge response 'public key' invalid.";
            return -1;
        }

        // Check for optional server challenge field existence and valid value.
        if (d.contains(msg::usrmsg::FLD_SERVER_CHALLENGE))
        {
            bool server_challenge_valid = false;

            if (d[msg::usrmsg::FLD_SERVER_CHALLENGE].is<std::string>())
            {
                std::string_view challenge = d[msg::usrmsg::FLD_SERVER_CHALLENGE].as<std::string_view>();

                if (!challenge.empty() && challenge.size() <= 32)
                {
                    server_challenge_valid = true;
                    extracted_server_challenge = challenge;
                }
            }

            if (!server_challenge_valid)
            {
                LOG_DEBUG << "User challenge response 'server_challenge' invalid.";
                return -1;
            }
        }

        // Check for protocol field existence and valid value.
        if (!d.contains(msg::usrmsg::FLD_PROTOCOL) || !d[msg::usrmsg::FLD_PROTOCOL].is<std::string>())
        {
            LOG_DEBUG << "User challenge response 'protocol' invalid.";
            return -1;
        }

        std::string_view protocolsv = d[msg::usrmsg::FLD_PROTOCOL].as<std::string_view>();
        if (protocolsv != "json" && protocolsv != "bson")
        {
            LOG_DEBUG << "User challenge response 'protocol' type invalid.";
            return -1;
        }

        // Verify the challenge signature. We do this last due to signature verification cost.

        std::string_view pubkey_hex = d[msg::usrmsg::FLD_PUBKEY].as<std::string_view>();
        const std::string pubkey_bytes = util::to_bin(pubkey_hex);

        std::string_view sig_hex = d[msg::usrmsg::FLD_SIG].as<std::string_view>();
        const std::string sig_bytes = util::to_bin(sig_hex);

        if (pubkey_bytes.empty() || sig_bytes.empty() || crypto::verify(original_challenge, sig_bytes, pubkey_bytes) != 0)
        {
            LOG_DEBUG << "User challenge response signature verification failed.";
            return -1;
        }

        extracted_pubkeyhex = pubkey_hex;
        extracted_protocol = protocolsv;

        return 0;
    }

    /**
     * Parses a json message sent by a user.
     * @param d Jsoncons document to which the parsed json should be loaded.
     * @param message The message to parse.
     *                Accepted message format:
     *                {
     *                  'type': '<message type>'
     *                  ...
     *                }
     * @return 0 on successful parsing. -1 for failure.
     */
    int parse_user_message(jsoncons::json &d, std::string_view message)
    {
        try
        {
            d = jsoncons::json::parse(message, jsoncons::strict_json_parsing());
        }
        catch (const std::exception &e)
        {
            LOG_DEBUG << "User json message parsing failed. " << e.what();
            return -1;
        }

        // Check existence of msg type field.
        if (!d.contains(msg::usrmsg::FLD_TYPE) || !d[msg::usrmsg::FLD_TYPE].is<std::string>())
        {
            LOG_DEBUG << "User json message 'type' missing or invalid.";
            return -1;
        }

        return 0;
    }

    /**
     * Extracts the message 'type' value from the json document.
     */
    int extract_type(std::string &extracted_type, const jsoncons::json &d)
    {
        extracted_type = d[msg::usrmsg::FLD_TYPE].as<std::string>();
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
     *            "content": "<any string>"
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_read_request(std::string &extracted_content, const jsoncons::json &d)
    {
        if (!d.contains(msg::usrmsg::FLD_CONTENT))
        {
            LOG_DEBUG << "Read request required fields missing.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_CONTENT].is<std::string>())
        {
            LOG_DEBUG << "Read request invalid field values.";
            return -1;
        }

        extracted_content = d[msg::usrmsg::FLD_CONTENT].as<std::string>();
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
     *            "input_container": "<stringified json input container>",
     *            "sig": "<hex encoded signature of stringified input container>"
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_signed_input_container(
        std::string &extracted_input_container, std::string &extracted_sig, const jsoncons::json &d)
    {
        if (!d.contains(msg::usrmsg::FLD_INPUT_CONTAINER) || !d.contains(msg::usrmsg::FLD_SIG))
        {
            LOG_DEBUG << "User signed input required fields missing.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_INPUT_CONTAINER].is<std::string>() || !d[msg::usrmsg::FLD_SIG].is<std::string>())
        {
            LOG_DEBUG << "User signed input invalid field values.";
            return -1;
        }

        // We do not verify the signature of the content here since we need to let each node
        // (including self) to verify that individually after we broadcast the NUP proposal.

        extracted_input_container = d[msg::usrmsg::FLD_INPUT_CONTAINER].as<std::string>();

        // Extract the hex signature and convert to binary.
        const std::string_view sig_hex = d[msg::usrmsg::FLD_SIG].as<std::string_view>();
        extracted_sig = util::to_bin(sig_hex);
        return 0;
    }

    /**
     * Extract the individual components of a given input container json.
     * @param input The extracted input.
     * @param nonce The extracted nonce.
     * @param max_lcl_seq_no The extracted max ledger sequence no.
     * @param contentjson The json string containing the input container message.
     *                    {
     *                      "input": "<any string>",
     *                      "nonce": "<random string with optional sorted order>",
     *                      "max_lcl_seq_no": <integer>
     *                    }
     * @return 0 on succesful extraction. -1 on failure.
     */
    int extract_input_container(std::string &input, std::string &nonce, uint64_t &max_lcl_seq_no, std::string_view contentjson)
    {
        jsoncons::json d;
        try
        {
            d = jsoncons::json::parse(contentjson, jsoncons::strict_json_parsing());
        }
        catch (const std::exception &e)
        {
            LOG_DEBUG << "User input container json parsing failed.";
            return -1;
        }

        if (!d.contains(msg::usrmsg::FLD_INPUT) || !d.contains(msg::usrmsg::FLD_NONCE) || !d.contains(msg::usrmsg::FLD_MAX_LCL_SEQ))
        {
            LOG_DEBUG << "User input container required fields missing.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_INPUT].is<std::string>() || !d[msg::usrmsg::FLD_NONCE].is<std::string>() || !d[msg::usrmsg::FLD_MAX_LCL_SEQ].is<uint64_t>())
        {
            LOG_DEBUG << "User input container invalid field values.";
            return -1;
        }

        input = d[msg::usrmsg::FLD_INPUT].as<std::string>();
        nonce = d[msg::usrmsg::FLD_NONCE].as<std::string>();
        max_lcl_seq_no = d[msg::usrmsg::FLD_MAX_LCL_SEQ].as<uint64_t>();

        return 0;
    }

    bool is_json_string(std::string_view content)
    {
        if (content.empty())
            return true;

        const char first = content[0];
        const char last = content[content.size() - 1];

        if ((first == '\"' && last == '\"') ||
            (first == '{' && last == '}') ||
            (first == '[' && last == ']') ||
            content == "true" || content == "false")
            return false;

        // Check whether all characters are digits.
        bool decimal_found = false;
        for (const char c : content)
        {
            if ((c != '.' && (c < '0' || c > '9')) || (c == '.' && decimal_found)) // Not a number.
                return true;
            else if (c == '.') // There can only be one decimal in a proper number.
                decimal_found = true;
        }

        return false; // Is a number.
    }

    void populate_output_hash_array(std::vector<uint8_t> &msg, const util::merkle_hash_node &node)
    {
        if (node.children.empty())
        {
            msg += "\"";
            msg += util::to_hex(node.hash);
            msg += "\"";
            return;
        }
        else
        {
            msg += "[";
            for (auto itr = node.children.begin(); itr != node.children.end(); itr++)
            {
                populate_output_hash_array(msg, *itr);
                if (std::next(itr) != node.children.end())
                    msg += ",";
            }
            msg += "]";
        }
    }

} // namespace msg::usrmsg::json