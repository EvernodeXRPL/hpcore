#include "../../conf.hpp"
#include "../../p2p/p2p.hpp"
#include "../../pchheader.hpp"
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
     *              "lcl_seq_no": <lcl sequence no>,
     *              "lcl_hash": <binary lcl hash>
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
        encoder.string_value(conf::cfg.hp_version);
        encoder.key(msg::usrmsg::FLD_LCL_SEQ);
        encoder.int64_value(lcl_seq_no);
        encoder.key(msg::usrmsg::FLD_LCL_HASH);
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
     *              "lcl_seq_no": <integer>,
     *              "lcl_hash": <binary lcl hash>
     *              "outputs": [<binary output 1>, <binary output 2>, ...], // The output order is the hash order.
     *              "hashes": [<binary merkle hash tree>], // Always includes user's output hash [output hash = hash(pubkey+all outputs for the user)]
     *              "unl_sig": [["<pubkey>", "<sig>"], ...] // Binary UNL pubkeys and signatures of root hash.
     *            }
     * @param content The contract binary output content to be put in the message.
     */
    void create_contract_output_container(std::vector<uint8_t> &msg, const ::std::vector<std::string_view> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash)
    {
        jsoncons::bson::bson_bytes_encoder encoder(msg);
        encoder.begin_object();
        encoder.key(msg::usrmsg::FLD_TYPE);
        encoder.string_value(msg::usrmsg::MSGTYPE_CONTRACT_OUTPUT);
        encoder.key(msg::usrmsg::FLD_LCL_SEQ);
        encoder.int64_value(lcl_seq_no);
        encoder.key(msg::usrmsg::FLD_LCL_HASH);
        encoder.byte_string_value(lcl_hash);

        encoder.key(msg::usrmsg::FLD_OUTPUTS);
        encoder.begin_array();
        for (int i = 0; i < outputs.size(); i++)
            encoder.byte_string_value(outputs[i]);
        encoder.end_array();

        encoder.key(msg::usrmsg::FLD_HASHES);
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
        populate_ledger_query_results(encoder, std::get<std::vector<ledger::query::query_result_record>>(result));
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
     * @param max_lcl_seq_no The extracted max ledger sequence no.
     * @param contentjson The bson input container message.
     *                    {
     *                      "input": <binary buffer>,
     *                      "nonce": "<random string with optional sorted order>",
     *                      "max_lcl_seq_no": <integer>
     *                    }
     * @return 0 on succesful extraction. -1 on failure.
     */
    int extract_input_container(std::string &input, std::string &nonce, uint64_t &max_lcl_seq_no, std::string_view contentbson)
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

        if (!d.contains(msg::usrmsg::FLD_INPUT) || !d.contains(msg::usrmsg::FLD_NONCE) || !d.contains(msg::usrmsg::FLD_MAX_LCL_SEQ))
        {
            LOG_DEBUG << "User input container required fields missing or invalid.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_INPUT].is_byte_string_view() || !d[msg::usrmsg::FLD_NONCE].is_string() || !d[msg::usrmsg::FLD_MAX_LCL_SEQ].is_uint64())
        {
            LOG_DEBUG << "User input container invalid field values.";
            return -1;
        }

        const jsoncons::byte_string_view &bsv = d[msg::usrmsg::FLD_INPUT].as_byte_string_view();
        input = std::string_view(reinterpret_cast<const char *>(bsv.data()), bsv.size());

        nonce = d[msg::usrmsg::FLD_NONCE].as<std::string>();
        max_lcl_seq_no = d[msg::usrmsg::FLD_MAX_LCL_SEQ].as<uint64_t>();
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
     *            "include": ["raw_inputs", "raw_outputs"]
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
        bool raw_inputs = false;
        bool raw_outputs = false;
        for (auto &val : d[msg::usrmsg::FLD_INCLUDE].array_range())
        {
            if (val == msg::usrmsg::FLD_RAW_INPUTS)
                raw_inputs = true;
            else if (val == msg::usrmsg::FLD_RAW_OUTPUTS)
                raw_outputs = true;
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
                raw_inputs,
                raw_outputs};
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

    void populate_ledger_query_results(jsoncons::bson::bson_bytes_encoder &encoder, const std::vector<ledger::query::query_result_record> &results)
    {
        for (const ledger::query::query_result_record &r : results)
        {
            encoder.begin_object();
            encoder.key(msg::usrmsg::FLD_SEQ_NO);
            encoder.uint64_value(r.ledger.seq_no);
            encoder.key(msg::usrmsg::FLD_TIMESTAMP);
            encoder.uint64_value(r.ledger.timestamp);
            encoder.key(msg::usrmsg::FLD_HASH);
            encoder.byte_string_value(r.ledger.ledger_hash);
            encoder.key(msg::usrmsg::FLD_PREV_HASH);
            encoder.byte_string_value(r.ledger.prev_ledger_hash);
            encoder.key(msg::usrmsg::FLD_STATE_HASH);
            encoder.byte_string_value(r.ledger.state_hash);
            encoder.key(msg::usrmsg::FLD_CONFIG_HASH);
            encoder.byte_string_value(r.ledger.config_hash);
            encoder.key(msg::usrmsg::FLD_USER_HASH);
            encoder.byte_string_value(r.ledger.user_hash);
            encoder.key(msg::usrmsg::FLD_INPUT_HASH);
            encoder.byte_string_value(r.ledger.input_hash);
            encoder.key(msg::usrmsg::FLD_OUTPUT_HASH);
            encoder.byte_string_value(r.ledger.output_hash);

            // If raw inputs or outputs is not requested, we don't include that field at all in the response.
            // Otherwise the field will always contain an array (empty array if no data).

            if (r.raw_inputs)
            {
                encoder.key(msg::usrmsg::FLD_RAW_INPUTS);
                populate_ledger_blob_map(encoder, *r.raw_inputs);
            }

            if (r.raw_outputs)
            {
                encoder.key(msg::usrmsg::FLD_RAW_OUTPUTS);
                populate_ledger_blob_map(encoder, *r.raw_outputs);
            }

            encoder.end_object();
        }
    }

    void populate_ledger_blob_map(jsoncons::bson::bson_bytes_encoder &encoder, const ledger::query::blob_map &blob_map)
    {
        encoder.begin_array();
        for (const auto &[pubkey, blobs] : blob_map)
        {
            encoder.begin_object();

            encoder.key(msg::usrmsg::FLD_PUBKEY);
            encoder.byte_string_value(pubkey);
            encoder.key(msg::usrmsg::FLD_BLOBS);
            encoder.begin_array();
            for (const std::string &blob : blobs)
                encoder.byte_string_value(blob);
            encoder.end_array();

            encoder.end_object();
        }
        encoder.end_array();
    }

} // namespace msg::usrmsg::bson