#include "../../conf.hpp"
#include "../../p2p/p2p.hpp"
#include "../../pchheader.hpp"
#include "../../util/version.hpp"
#include "../../util/util.hpp"
#include "../../hplog.hpp"
#include "../../ledger/ledger_query.hpp"
#include "../usrmsg_common.hpp"
#include "usrmsg_bson.hpp"

namespace msg::usrmsg::bson
{
    /**
     * Constructs a status response message.
     * @param msg Buffer to construct the generated bson message into.
     *            Message format:
     *            {
     *              "type": "stat_response",
     *              "ledger_seq_no": <lcl sequence no>,
     *              "ledger_hash": <binary lcl hash>
     *            }
     */
    constexpr const size_t MAX_KNOWN_PEERS_INFO = 10;

    void create_status_response(std::vector<uint8_t> &msg, const uint64_t lcl_seq_no, std::string_view lcl_hash)
    {
        jsoncons::bson::bson_bytes_encoder encoder(msg);
        encoder.begin_object();
        encoder.key(msg::usrmsg::FLD_TYPE);
        encoder.string_value(msg::usrmsg::MSGTYPE_STAT_RESPONSE);
        encoder.key(msg::usrmsg::FLD_HP_VERSION);
        encoder.string_value(version::HP_VERSION);
        encoder.key(msg::usrmsg::FLD_LEDGER_SEQ_NO);
        encoder.int64_value(lcl_seq_no);
        encoder.key(msg::usrmsg::FLD_LEDGER_HASH);
        encoder.byte_string_value(lcl_hash);
        encoder.key(msg::usrmsg::FLD_ROUND_TIME);
        encoder.uint64_value(conf::cfg.contract.roundtime);
        encoder.key(msg::usrmsg::FLD_CONTARCT_EXECUTION_ENABLED);
        encoder.bool_value(conf::cfg.contract.execute);
        encoder.key(msg::usrmsg::FLD_READ_REQUESTS_ENABLED);
        encoder.bool_value(conf::cfg.user.concurrent_read_reqeuests != 0);
        encoder.key(msg::usrmsg::FLD_IS_FULL_HISTORY_NODE);
        encoder.bool_value(conf::cfg.node.history == conf::HISTORY::FULL);

        encoder.key(msg::usrmsg::FLD_CURRENT_UNL);
        encoder.begin_array();
        for (std::string_view unl : conf::cfg.contract.unl)
            encoder.byte_string_value(unl);
        encoder.end_array();
        encoder.key(msg::usrmsg::FLD_PEERS);

        {
            std::scoped_lock<std::mutex> lock(p2p::ctx.peer_connections_mutex);

            const size_t max_peers_count = MIN(MAX_KNOWN_PEERS_INFO, p2p::ctx.peer_connections.size());
            size_t count = 1;

            encoder.begin_array();
            // Currently all peers, up to a max of 10 are sent regardless of state.
            for (auto peer = p2p::ctx.peer_connections.begin(); peer != p2p::ctx.peer_connections.end() && count <= max_peers_count; peer++, count++)
                encoder.string_value(peer->second->known_ipport->host_address + ":" + std::to_string(peer->second->known_ipport->port));
            encoder.end_array();
        }

        encoder.end_object();
        encoder.flush();
    }

    /**
     * Constructs a contract input status message.
     * @param msg Buffer to construct the generated bson message into.
     *            Message format:
     *            {
     *              "type": "contract_input_status",
     *              "status": "<accepted|rejected>",
     *              "reason": "<reson>",
     *              "input_hash": <hash of original input signature>,
     *              "ledger_seq_no": <sequence no of the ledger that the input got included in>,
     *              "ledger_hash": "<hash no of the ledger that the input got included in>"
     *            }
     * @param is_accepted Whether the original message was accepted or not.
     * @param reason Rejected reason. Empty if accepted.
     * @param input_hash Binary Hash of the original input signature. This is used by user
     *                   to tie the response with the input submission.
     */
    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                      std::string_view input_hash, const uint64_t ledger_seq_no, const util::h32 &ledger_hash)
    {
        jsoncons::bson::bson_bytes_encoder encoder(msg);
        encoder.begin_object();
        encoder.key(msg::usrmsg::FLD_TYPE);
        encoder.string_value(msg::usrmsg::MSGTYPE_CONTRACT_INPUT_STATUS);
        encoder.key(msg::usrmsg::FLD_STATUS);
        encoder.string_value(status);

        // Reject reason is only included for rejected inputs.
        if (!reason.empty())
        {
            encoder.key(msg::usrmsg::FLD_REASON);
            encoder.string_value(reason);
        }

        encoder.key(msg::usrmsg::FLD_INPUT_HASH);
        encoder.byte_string_value(input_hash);

        // Ledger information is only included in 'accepted' input statuses.
        if (ledger_seq_no > 0)
        {
            encoder.key(msg::usrmsg::FLD_LEDGER_SEQ_NO);
            encoder.uint64_value(ledger_seq_no);
            encoder.key(msg::usrmsg::FLD_LEDGER_HASH);
            encoder.byte_string_value(ledger_hash.to_string_view());
        }

        encoder.end_object();
        encoder.flush();
    }

    /**
     * Constructs a contract read response message.
     * @param msg Buffer to construct the generated bson message into.
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
     * @param msg Buffer to construct the generated bson message into.
     *            Message format:
     *            {
     *              "type": "contract_output",
     *              "ledger_seq_no": <integer>,
     *              "ledger_hash": <binary lcl hash>,
     *              "outputs": [<binary output 1>, <binary output 2>, ...], // The output order is the hash generation order.
     *              "output_hash": <binary hash of user's outputs>,  [output hash = hash(pubkey+all outputs for the user)]
     *              "hash_tree": [<binary merkle hash tree for this round>], // Collapsed merkle tree with user's hash element marked as null. 
     *              "unl_sig": [["<pubkey>", "<sig>"], ...] // Binary UNL pubkeys and signatures of root hash.
     *            }
     * @param hash This user's combined output hash. [output hash = hash(pubkey+all outputs for the user)]
     * @param outputs List of outputs for the user.
     * @param hash_root Root node of the collapsed merkle hash tree for this round.
     * @param unl_sig List of unl signatures issued on the root hash. (root hash = merkle root hash of hashes of all users)
     * @param lcl_seq_no Current ledger seq no.
     * @param lcl_hash Current ledger hash.
     */
    void create_contract_output_container(std::vector<uint8_t> &msg, std::string_view hash, const ::std::vector<std::string> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash)
    {
        jsoncons::bson::bson_bytes_encoder encoder(msg);
        encoder.begin_object();
        encoder.key(msg::usrmsg::FLD_TYPE);
        encoder.string_value(msg::usrmsg::MSGTYPE_CONTRACT_OUTPUT);
        encoder.key(msg::usrmsg::FLD_LEDGER_SEQ_NO);
        encoder.int64_value(lcl_seq_no);
        encoder.key(msg::usrmsg::FLD_LEDGER_HASH);
        encoder.byte_string_value(lcl_hash);

        encoder.key(msg::usrmsg::FLD_OUTPUTS);
        encoder.begin_array();
        for (int i = 0; i < outputs.size(); i++)
            encoder.byte_string_value(outputs[i]);
        encoder.end_array();

        encoder.key(msg::usrmsg::FLD_OUTPUT_HASH);
        encoder.byte_string_value(hash);

        encoder.key(msg::usrmsg::FLD_HASH_TREE);
        populate_output_hash_array(encoder, hash_root);

        encoder.key(msg::usrmsg::FLD_UNL_SIG);
        encoder.begin_array();
        for (const auto &[pubkey, sig] : unl_sig)
        {
            encoder.begin_array();
            encoder.byte_string_value(pubkey);
            encoder.byte_string_value(sig);
            encoder.end_array();
        }
        encoder.end_array();

        encoder.end_object();
        encoder.flush();
    }

    /**
     * Constructs unl list container message.
     * @param msg Buffer to construct the generated bson message string into.
     *            Message format:
     *            {
     *              "type": "unl_change",
     *              "unl": ["<pubkey1>{[1byte(11101101) prefix][32byte]}", ...] // Binary pubkey list of unl nodes.
     *            }
     * @param unl_list The unl node pubkey list to be put in the message.
     */
    void create_unl_list_container(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list)
    {
        jsoncons::bson::bson_bytes_encoder encoder(msg);
        encoder.begin_object();
        encoder.key(msg::usrmsg::FLD_TYPE);
        encoder.string_value(msg::usrmsg::MSGTYPE_UNL_CHANGE);
        encoder.key(msg::usrmsg::FLD_UNL);
        encoder.begin_array();
        for (std::string_view unl : unl_list)
            encoder.byte_string_value(unl);
        encoder.end_array();
        encoder.end_object();
        encoder.flush();
    }

    /**
     * Constructs a ledger query response.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "ledger_query_result",
     *              "reply_for": "<original query id>",
     *              "error": "error_code" or NULL,
     *              "results": [{}...]
     *            }
     * @param reply_for Original query id to associate the response with.
     * @param result Query results to be sent in the response.
     */
    void create_ledger_query_response(std::vector<uint8_t> &msg, std::string_view reply_for,
                                      const ledger::query::query_result &result)
    {
        jsoncons::bson::bson_bytes_encoder encoder(msg);
        encoder.begin_object();
        encoder.key(msg::usrmsg::FLD_TYPE);
        encoder.string_value(msg::usrmsg::MSGTYPE_LEDGER_QUERY_RESULT);
        encoder.key(msg::usrmsg::FLD_REPLY_FOR);
        encoder.string_value(reply_for);
        encoder.key(msg::usrmsg::FLD_ERROR);
        if (result.index() == 1)
            encoder.null_value();
        else
            encoder.string_value(std::get<const char *>(result));

        encoder.key(msg::usrmsg::FLD_RESULTS);
        encoder.begin_array();
        populate_ledger_query_results(encoder, std::get<std::vector<ledger::ledger_record>>(result));
        encoder.end_array();
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
            LOG_DEBUG << "User bson message parsing failed.";
            return -1;
        }

        if (!d.contains(FLD_TYPE) || !d[FLD_TYPE].is_string())
        {
            LOG_DEBUG << "User bson message 'type' missing or invalid.";
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
     *            "content": <binary buffer>
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_read_request(std::string &extracted_content, const jsoncons::ojson &d)
    {
        if (!d.contains(msg::usrmsg::FLD_CONTENT) || !d[msg::usrmsg::FLD_CONTENT].is_byte_string_view())
        {
            LOG_DEBUG << "Read request 'content' field missing or invalid.";
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
     *            "input_container": <bson serialized input container>,
     *            "sig": <binary signature buffer of the bson serialized content>
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_signed_input_container(
        std::string &extracted_input_container, std::string &extracted_sig, const jsoncons::ojson &d)
    {
        if (!d.contains(msg::usrmsg::FLD_INPUT_CONTAINER) || !d.contains(msg::usrmsg::FLD_SIG) ||
            !d[msg::usrmsg::FLD_INPUT_CONTAINER].is_byte_string_view() || !d[msg::usrmsg::FLD_SIG].is_byte_string_view())
        {
            LOG_DEBUG << "User signed input required fields missing or invalid.";
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
     * @param max_ledger_seq_no The extracted max ledger sequence no.
     * @param contentjson The bson input container message.
     *                    {
     *                      "input": <binary buffer>,
     *                      "nonce": <integer>, // Indicates input ordering.
     *                      "max_ledger_seq_no": <integer>
     *                    }
     * @return 0 on succesful extraction. -1 on failure.
     */
    int extract_input_container(std::string &input, uint64_t &nonce, uint64_t &max_ledger_seq_no, std::string_view contentbson)
    {
        jsoncons::ojson d;
        try
        {
            d = jsoncons::bson::decode_bson<jsoncons::ojson>(contentbson);
        }
        catch (const std::exception &e)
        {
            LOG_DEBUG << "User input container bson parsing failed.";
            return -1;
        }

        if (!d.contains(msg::usrmsg::FLD_INPUT) || !d.contains(msg::usrmsg::FLD_NONCE) || !d.contains(msg::usrmsg::FLD_MAX_LEDGER_SEQ_NO))
        {
            LOG_DEBUG << "User input container required fields missing or invalid.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_INPUT].is_byte_string_view() || !d[msg::usrmsg::FLD_NONCE].is_uint64() || !d[msg::usrmsg::FLD_MAX_LEDGER_SEQ_NO].is_uint64())
        {
            LOG_DEBUG << "User input container invalid field values.";
            return -1;
        }

        const jsoncons::byte_string_view &bsv = d[msg::usrmsg::FLD_INPUT].as_byte_string_view();
        input = std::string_view(reinterpret_cast<const char *>(bsv.data()), bsv.size());

        nonce = d[msg::usrmsg::FLD_NONCE].as<uint64_t>();
        max_ledger_seq_no = d[msg::usrmsg::FLD_MAX_LEDGER_SEQ_NO].as<uint64_t>();
        return 0;
    }

    /**
     * Extract query information from a ledger query request.
     * @param extracted_query Extracted query criteria.
     * @param extracted_id The query id.
     * @param d The bson document holding the query.
     *          Accepted query message format:
     *          {
     *            "type": "ledger_query",
     *            "id": "<query id>",
     *            "filter_by": "<filter by>",
     *            "params": {...}, // Params supported by the specified filter.
     *            "include": ["inputs", "outputs"]
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_ledger_query(ledger::query::query_request &extracted_query, std::string &extracted_id, const jsoncons::ojson &d)
    {
        if (!d.contains(msg::usrmsg::FLD_ID) || !d.contains(msg::usrmsg::FLD_FILTER_BY) ||
            !d.contains(msg::usrmsg::FLD_PARAMS) || !d.contains(msg::usrmsg::FLD_INCLUDE))
        {
            LOG_DEBUG << "Ledger query required fields missing.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_ID].is<std::string>() || !d[msg::usrmsg::FLD_FILTER_BY].is<std::string>() ||
            !d[msg::usrmsg::FLD_PARAMS].is_object() || !d[msg::usrmsg::FLD_INCLUDE].is_array())
        {
            LOG_DEBUG << "Ledger query invalid field values.";
            return -1;
        }

        const std::string id = d[msg::usrmsg::FLD_ID].as<std::string>();
        if (id.empty())
        {
            LOG_DEBUG << "Ledger query invalid id.";
            return -1;
        }
        extracted_id = std::move(id);

        // Detect includes.
        bool inputs = false;
        bool outputs = false;
        for (auto &val : d[msg::usrmsg::FLD_INCLUDE].array_range())
        {
            if (val == msg::usrmsg::FLD_INPUTS)
                inputs = true;
            else if (val == msg::usrmsg::FLD_OUTPUTS)
                outputs = true;
        }

        auto &params_field = d[msg::usrmsg::FLD_PARAMS];

        if (d[msg::usrmsg::FLD_FILTER_BY] == msg::usrmsg::QUERY_FILTER_BY_SEQ_NO)
        {
            if (!params_field.contains(msg::usrmsg::FLD_SEQ_NO) || !params_field[msg::usrmsg::FLD_SEQ_NO].is<uint64_t>())
            {
                LOG_DEBUG << "Ledger query seq no filter invalid params.";
                return -1;
            }

            extracted_query = ledger::query::seq_no_query{
                params_field[msg::usrmsg::FLD_SEQ_NO].as<uint64_t>(),
                inputs,
                outputs};
            return 0;
        }
        else
        {
            LOG_DEBUG << "Ledger query invalid filter-by criteria.";
            return -1;
        }
    }

    void populate_output_hash_array(jsoncons::bson::bson_bytes_encoder &encoder, const util::merkle_hash_node &node)
    {
        if (node.children.empty())
        {
            // The retained node is serialized as null.
            // This is so the client can identify the self-hash position within the hash tree.
            if (node.is_retained)
                encoder.null_value();
            else
                encoder.byte_string_value(node.hash);
            return;
        }
        else
        {
            encoder.begin_array();
            for (const auto &child : node.children)
                populate_output_hash_array(encoder, child);
            encoder.end_array();
        }
    }

    void populate_ledger_query_results(jsoncons::bson::bson_bytes_encoder &encoder, const std::vector<ledger::ledger_record> &results)
    {
        for (const ledger::ledger_record &ledger : results)
        {
            encoder.begin_object();
            encoder.key(msg::usrmsg::FLD_SEQ_NO);
            encoder.uint64_value(ledger.seq_no);
            encoder.key(msg::usrmsg::FLD_TIMESTAMP);
            encoder.uint64_value(ledger.timestamp);
            encoder.key(msg::usrmsg::FLD_HASH);
            encoder.byte_string_value(ledger.ledger_hash);
            encoder.key(msg::usrmsg::FLD_PREV_HASH);
            encoder.byte_string_value(ledger.prev_ledger_hash);
            encoder.key(msg::usrmsg::FLD_STATE_HASH);
            encoder.byte_string_value(ledger.state_hash);
            encoder.key(msg::usrmsg::FLD_CONFIG_HASH);
            encoder.byte_string_value(ledger.config_hash);
            encoder.key(msg::usrmsg::FLD_USER_HASH);
            encoder.byte_string_value(ledger.user_hash);
            encoder.key(msg::usrmsg::FLD_INPUT_HASH);
            encoder.byte_string_value(ledger.input_hash);
            encoder.key(msg::usrmsg::FLD_OUTPUT_HASH);
            encoder.byte_string_value(ledger.output_hash);

            // If raw inputs or outputs is not requested, we don't include that field at all in the response.
            // Otherwise the field will always contain an array (empty array if no data).

            if (ledger.inputs)
            {
                encoder.key(msg::usrmsg::FLD_INPUTS);
                populate_ledger_inputs(encoder, *ledger.inputs);
            }

            if (ledger.outputs)
            {
                encoder.key(msg::usrmsg::FLD_OUTPUTS);
                populate_ledger_outputs(encoder, *ledger.outputs);
            }

            encoder.end_object();
        }
    }

    void populate_ledger_inputs(jsoncons::bson::bson_bytes_encoder &encoder, const std::vector<ledger::ledger_user_input> &inputs)
    {
        encoder.begin_array();
        for (const ledger::ledger_user_input &inp : inputs)
        {
            encoder.begin_object();

            encoder.key(msg::usrmsg::FLD_PUBKEY);
            encoder.byte_string_value(inp.pubkey);
            encoder.key(msg::usrmsg::FLD_HASH);
            encoder.byte_string_value(inp.hash);
            encoder.key(msg::usrmsg::FLD_NONCE);
            encoder.uint64_value(inp.nonce);
            encoder.key(msg::usrmsg::FLD_BLOB);
            encoder.byte_string_value(inp.blob);

            encoder.end_object();
        }
        encoder.end_array();
    }

    void populate_ledger_outputs(jsoncons::bson::bson_bytes_encoder &encoder, const std::vector<ledger::ledger_user_output> &users)
    {
        encoder.begin_array();
        for (const ledger::ledger_user_output &user : users)
        {
            encoder.begin_object();

            encoder.key(msg::usrmsg::FLD_PUBKEY);
            encoder.byte_string_value(user.pubkey);
            encoder.key(msg::usrmsg::FLD_HASH);
            encoder.byte_string_value(user.hash);
            encoder.key(msg::usrmsg::FLD_BLOBS);
            encoder.begin_array();
            for (const std::string &output : user.outputs)
                encoder.byte_string_value(output);
            encoder.end_array();

            encoder.end_object();
        }
        encoder.end_array();
    }

} // namespace msg::usrmsg::bson