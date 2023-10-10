#include "../../pchheader.hpp"
#include "../../util/version.hpp"
#include "../../util/sequence_hash.hpp"
#include "../../util/util.hpp"
#include "../../util/merkle_hash_tree.hpp"
#include "../../unl.hpp"
#include "../../crypto.hpp"
#include "../../hplog.hpp"
#include "../../conf.hpp"
#include "../../ledger/ledger_query.hpp"
#include "../../status.hpp"
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
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "hp_version": "<hp protocol version>",
     *              "type": "user_challenge",
     *              "contract_id": "<contract id>",
     *              "contract_version": "<contract version string>",
     *              "challenge": "<challenge string>"
     *            }
     * @param challenge_bytes Buffer to construct the generated challenge bytes into.
     */
    void create_user_challenge(std::vector<uint8_t> &msg, std::string &challenge)
    {
        std::string challenge_bytes;
        crypto::random_bytes(challenge_bytes, msg::usrmsg::CHALLENGE_LEN);
        challenge = util::to_hex(challenge_bytes);

        // Construct the challenge msg json.
        // We do not use jsoncons library here in favour of performance because this is a simple json message.

        // Since we know the rough size of the challenge message we reserve adequate amount for the holder.
        // Only HotPocket version number is variable length.
        msg.reserve(256);
        msg += "{\"";
        msg += msg::usrmsg::FLD_HP_VERSION;
        msg += SEP_COLON;
        msg += version::HP_VERSION;
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
     * @param msg Buffer to construct the generated json message string into.
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
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "stat_response",
     *              "hp_version": "<version>",
     *              "ledger_seq_no": <lcl sequence no>,
     *              "ledger_hash": "<lcl hash hex>",
     *              "vote_status": "synced" | "desync" | "unreliable",
     *              "roundtime": <roundtime milliseconds>,
     *              "contract_execution_enabled": true | false,
     *              "read_requests_enabled": true | false,
     *              "is_full_history_node": true | false,
     *              "weakly_connected": true | false,
     *              "current_unl": [ "<ed prefixed pubkey hex>"", ... ],
     *              "peers": [ "ip:port", ... ]
     *            }
     */
    void create_status_response(std::vector<uint8_t> &msg)
    {
        const util::sequence_hash lcl_id = status::get_lcl_id();
        const std::set<std::string> unl = status::get_unl();
        const status::VOTE_STATUS vote_status = status::get_vote_status();
        const bool weakly_connected = status::get_weakly_connected();

        msg.reserve(1024);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_STAT_RESPONSE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_HP_VERSION;
        msg += SEP_COLON;
        msg += version::HP_VERSION;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_LEDGER_SEQ_NO;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(lcl_id.seq_no);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_LEDGER_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(lcl_id.hash.to_string_view());
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_VOTE_STATUS;
        msg += SEP_COLON;
        msg += msg::usrmsg::VOTE_STATUSES[vote_status];
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_ROUND_TIME;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(conf::cfg.contract.consensus.roundtime);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_CONTARCT_EXECUTION_ENABLED;
        msg += SEP_COLON_NOQUOTE;
        msg += conf::cfg.contract.execute ? STR_TRUE : STR_FALSE;
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_READ_REQUESTS_ENABLED;
        msg += SEP_COLON_NOQUOTE;
        msg += conf::cfg.user.concurrent_read_requests != 0 ? STR_TRUE : STR_FALSE;
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_IS_FULL_HISTORY_NODE;
        msg += SEP_COLON_NOQUOTE;
        msg += conf::cfg.node.history == conf::HISTORY::FULL ? STR_TRUE : STR_FALSE;
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_WEAKLY_CONNECTED;
        msg += SEP_COLON_NOQUOTE;
        msg += weakly_connected ? STR_TRUE : STR_FALSE;
        msg += SEP_COMMA_NOQUOTE;

        msg += msg::usrmsg::FLD_CURRENT_UNL;
        msg += SEP_COLON_NOQUOTE;
        msg += OPEN_SQR_BRACKET;

        for (auto pubkey = unl.begin(); pubkey != unl.end(); pubkey++)
        {
            msg += DOUBLE_QUOTE + util::to_hex(*pubkey) + DOUBLE_QUOTE;

            if (std::next(pubkey) != unl.end())
                msg += ",";
        }

        msg += CLOSE_SQR_BRACKET;
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_PEERS;
        msg += SEP_COLON_NOQUOTE;
        msg += OPEN_SQR_BRACKET;

        {
            const std::set<conf::peer_ip_port> peers = status::get_peers();
            const size_t max_peers_count = MIN(MAX_KNOWN_PEERS_INFO, peers.size());
            size_t count = 1;

            for (auto peer = peers.begin(); peer != peers.end() && count <= max_peers_count; peer++)
            {
                if (count > 1)
                    msg += ",";
                msg += DOUBLE_QUOTE + peer->to_string() + DOUBLE_QUOTE;
                count++;
            }
        }

        msg += CLOSE_SQR_BRACKET;
        msg += "}";
    }

    /**
     * Constructs a lcl response message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "lcl_response",
     *              "ledger_seq_no": <lcl sequence no>,
     *              "ledger_hash": "<lcl hash hex>"
     *            }
     */
    void create_lcl_response(std::vector<uint8_t> &msg)
    {
        const util::sequence_hash lcl_id = status::get_lcl_id();

        msg.reserve(512);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_LCL_RESPONSE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_LEDGER_SEQ_NO;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(lcl_id.seq_no);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_LEDGER_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(lcl_id.hash.to_string_view());
        msg += "\"}";
    }

    /**
     * Constructs a contract input status message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "contract_input_status",
     *              "status": "<accepted|rejected>",
     *              "reason": "<reson>",
     *              "input_hash": "<hex hash of original input signature>",
     *              "ledger_seq_no": <sequence no of the ledger that the input got included in>,
     *              "ledger_hash": "<hex hash no of the ledger that the input got included in>"
     *            }
     * @param is_accepted Whether the original message was accepted or not.
     * @param reason Rejected reason. Empty if accepted.
     * @param input_hash Binary Hash of the original input signature. This is used by user
     *                   to tie the response with the input submission.
     */
    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                      std::string_view input_hash, const uint64_t ledger_seq_no, const util::h32 &ledger_hash)
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

        // Reject reason is only included for rejected inputs.
        if (!reason.empty())
        {
            msg += msg::usrmsg::FLD_REASON;
            msg += SEP_COLON;
            msg += reason;
            msg += SEP_COMMA;
        }

        msg += msg::usrmsg::FLD_INPUT_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(input_hash);

        // Ledger information is only included in 'accepted' input statuses.
        if (ledger_seq_no > 0)
        {
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_LEDGER_SEQ_NO;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(ledger_seq_no);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_LEDGER_HASH;
            msg += SEP_COLON;
            msg += util::to_hex(ledger_hash.to_string_view());
        }

        msg += "\"}";
    }

    /**
     * Constructs a contract read response message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "contract_read_response",
     *              "reply_for": "<corresponding request id>",
     *              "content": "<response string>"
     *            }
     * @param content The contract binary output content to be put in the message.
     */
    void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view reply_for, std::string_view content)
    {
        msg.reserve(content.size() + 256);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_CONTRACT_READ_RESPONSE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_REPLY_FOR;
        msg += SEP_COLON;
        msg += reply_for;
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
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "contract_output",
     *              "ledger_seq_no": <integer>,
     *              "ledger_hash": "<lcl hash hex>",
     *              "outputs": ["<output string 1>", "<output string 2>", ...], // The output order is the hash generation order.
     *              "output_hash": "<hex hash of user's outputs>",  [output hash = hash(pubkey+all outputs for the user)]
     *              "hash_tree": [<hex merkle hash tree>], // Collapsed merkle tree with user's hash element marked as null. 
     *              "unl_sig": [["<pubkey hex>", "<sig hex>"], ...] // UNL pubkeys and signatures of root hash.
     *            }
     * @param hash This user's combined output hash. [output hash = hash(pubkey+all outputs for the user)]
     * @param outputs List of outputs for the user.
     * @param hash_root Root node of the collapsed merkle hash tree.
     * @param unl_sig List of unl signatures issued on the root hash. (root hash = combined merkle hash of hashes of all users)
     * @param lcl_seq_no Current ledger seq no.
     * @param lcl_hash Current ledger hash.
     */
    void create_contract_output_container(std::vector<uint8_t> &msg, std::string_view hash, const ::std::vector<std::string> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash)
    {
        msg.reserve(1024);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_CONTRACT_OUTPUT;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_LEDGER_SEQ_NO;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(lcl_seq_no);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_LEDGER_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(lcl_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_OUTPUTS;
        msg += "\":[";

        for (size_t i = 0; i < outputs.size(); i++)
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

        msg += msg::usrmsg::FLD_OUTPUT_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(hash);
        msg += SEP_COMMA;

        msg += msg::usrmsg::FLD_HASH_TREE;
        msg += SEP_COLON_NOQUOTE;
        populate_output_hash_array(msg, hash_root);
        msg += SEP_COMMA_NOQUOTE;

        msg += msg::usrmsg::FLD_UNL_SIG;
        msg += "\":[";
        for (size_t i = 0; i < unl_sig.size(); i++)
        {
            const auto &sig = unl_sig[i]; // Pubkey and Signature pair.
            msg += "[\"";
            msg += util::to_hex(sig.first);
            msg += SEP_COMMA;
            msg += util::to_hex(sig.second);
            msg += "\"]";

            if (i < unl_sig.size() - 1)
                msg += ",";
        }
        msg += "]}";
    }

    /**
     * Constructs unl change notification message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "unl_change",
     *              "unl": ["<pubkey1>{[ed prefix][64 characters]}", ...] // Hex pubkey list of unl nodes.
     *            }
     * @param unl_list The unl node pubkey list to be put in the message.
     */
    void create_unl_notification(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list)
    {
        msg.reserve((69 * unl_list.size()) + 30);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_UNL_CHANGE;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_UNL;
        msg += "\":[";

        size_t i = 0;
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
     * Constructs ledger created notification message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "ledger_event",
     *              "event": "ledger_created",
     *              "ledger": { ... }
     *            }
     * @param ledger The created ledger.
     */
    void create_ledger_created_notification(std::vector<uint8_t> &msg, const ledger::ledger_record &ledger)
    {
        msg.reserve(1024);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_LEDGER_EVENT;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_EVENT;
        msg += SEP_COLON;
        msg += msg::usrmsg::LEDGER_EVENT_LEDGER_CREATED;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_LEDGER;
        msg += "\":{";
        populate_ledger_fields(msg, ledger);
        msg += "}}";
    }

    /**
     * Constructs sync status notification message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "ledger_event",
     *              "event": "vote_status",
     *              "vote_status": "synced" | "desync" | "unreliable"
     *            }
     * @param in_sync Whether the node is in sync or not.
     */
    void create_vote_status_notification(std::vector<uint8_t> &msg, const status::VOTE_STATUS vote_status)
    {
        msg.reserve(128);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_LEDGER_EVENT;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_EVENT;
        msg += SEP_COLON;
        msg += msg::usrmsg::LEDGER_EVENT_VOTE_STATUS;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_VOTE_STATUS;
        msg += SEP_COLON;
        msg += msg::usrmsg::VOTE_STATUSES[vote_status];
        msg += "\"}";
    }

    /**
     * Constructs health stat message.
     * @param msg Buffer to construct the generated json message string into.
     *            Message format:
     *            {
     *              "type": "health_event",
     *              "event": "proposal" | "connectivity",
     * 
     *              // proposal
     *              "comm_latency": {min:0, max:0, avg:0},
     *              "read_latency": {min:0, max:0, avg:0}
     *              "batch_size": 0
     * 
     *              // connectivity
     *              "peer_count": 0,
     *              "weakly_connected": true | false
     *            }
     * @param ev Current health information.
     */
    void create_health_notification(std::vector<uint8_t> &msg, const status::health_event &ev)
    {
        msg.reserve(128);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_HEALTH_EVENT;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_EVENT;
        msg += SEP_COLON;

        if (ev.index() == 0)
        {
            const status::proposal_health &phealth = std::get<status::proposal_health>(ev);

            msg += msg::usrmsg::HEALTH_EVENT_PROPOSAL;
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_COMM_LATENCY;
            msg += SEP_COLON_NOQUOTE;
            msg += "{\"";
            msg += msg::usrmsg::FLD_MIN;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.comm_latency_min);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_MAX;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.comm_latency_max);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_AVG;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.comm_latency_avg);
            msg += "}";

            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_READ_LATENCY;
            msg += SEP_COLON_NOQUOTE;
            msg += "{\"";
            msg += msg::usrmsg::FLD_MIN;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.read_latency_min);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_MAX;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.read_latency_max);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_AVG;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.read_latency_avg);
            msg += "}";

            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_BATCH_SIZE;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(phealth.batch_size);
        }
        else if (ev.index() == 1)
        {
            const status::connectivity_health &conn = std::get<status::connectivity_health>(ev);
            msg += msg::usrmsg::HEALTH_EVENT_CONNECTIVITY;
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_PEER_COUNT;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(conn.peer_count);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_WEAKLY_CONNECTED;
            msg += SEP_COLON_NOQUOTE;
            msg += conn.is_weakly_connected ? STR_TRUE : STR_FALSE;
        }

        msg += "}";
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
        msg.reserve(1024);
        msg += "{\"";
        msg += msg::usrmsg::FLD_TYPE;
        msg += SEP_COLON;
        msg += msg::usrmsg::MSGTYPE_LEDGER_QUERY_RESULT;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_REPLY_FOR;
        msg += SEP_COLON;
        msg += reply_for;
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_ERROR;
        if (result.index() == 1)
        {
            msg += "\":null,\"";
        }
        else
        {
            msg += SEP_COLON;
            msg += std::get<const char *>(result);
            msg += SEP_COMMA;
        }
        msg += msg::usrmsg::FLD_RESULTS;
        msg += "\":[";
        if (result.index() == 1)
            populate_ledger_query_results(msg, std::get<std::vector<ledger::ledger_record>>(result));
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
     *            "id": "<any string>",
     *            "content": "<any string>"
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_read_request(std::string &extracted_id, std::string &extracted_content, const jsoncons::json &d)
    {
        if (!d.contains(msg::usrmsg::FLD_ID) || !d[msg::usrmsg::FLD_ID].is<std::string>())
        {
            LOG_DEBUG << "Read request 'id' field missing or invalid.";
            return -1;
        }

        if (!d.contains(msg::usrmsg::FLD_CONTENT) || !d[msg::usrmsg::FLD_CONTENT].is<std::string>())
        {
            LOG_DEBUG << "Read request 'content' field missing or invalid.";
            return -1;
        }

        extracted_id = d[msg::usrmsg::FLD_ID].as<std::string>();
        extracted_content = d[msg::usrmsg::FLD_CONTENT].as<std::string>();
        return 0;
    }

        /**
     * Extracts a contract shell input message sent by user.
     * 
     * @param extracted_content The content to be passed to the contract, extracted from the message.
     * @param d The json document holding the shell input message.
     *          Accepted signed input container format:
     *          {
     *            "type": "contract_shell_input",
     *            "id": "<any string>",
     *            "content": "<any string>"
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_shell_input(std::string &extracted_id, std::string &extracted_content, const jsoncons::json &d)
    {
        if (!d.contains(msg::usrmsg::FLD_ID) || !d[msg::usrmsg::FLD_ID].is<std::string>())
        {
            LOG_DEBUG << "Shell input 'id' field missing or invalid.";
            return -1;
        }

        if (!d.contains(msg::usrmsg::FLD_CONTENT) || !d[msg::usrmsg::FLD_CONTENT].is<std::string>())
        {
            LOG_DEBUG << "Shell input 'content' field missing or invalid.";
            return -1;
        }

        extracted_id = d[msg::usrmsg::FLD_ID].as<std::string>();
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
     * @param max_ledger_seq_no The extracted max ledger sequence no.
     * @param contentjson The json string containing the input container message.
     *                    {
     *                      "input": "<any string>",
     *                      "nonce": <integer>, // Indicates input ordering.
     *                      "max_ledger_seq_no": <integer>
     *                    }
     * @return 0 on succesful extraction. -1 on failure.
     */
    int extract_input_container(std::string &input, uint64_t &nonce, uint64_t &max_ledger_seq_no, std::string_view contentjson)
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

        if (!d.contains(msg::usrmsg::FLD_INPUT) || !d.contains(msg::usrmsg::FLD_NONCE) || !d.contains(msg::usrmsg::FLD_MAX_LEDGER_SEQ_NO))
        {
            LOG_DEBUG << "User input container required fields missing.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_INPUT].is<std::string>() || !d[msg::usrmsg::FLD_NONCE].is<uint64_t>() || !d[msg::usrmsg::FLD_MAX_LEDGER_SEQ_NO].is<uint64_t>())
        {
            LOG_DEBUG << "User input container invalid field values.";
            return -1;
        }

        nonce = d[msg::usrmsg::FLD_NONCE].as<uint64_t>();
        if (nonce == 0)
        {
            LOG_DEBUG << "Input nonce must be a positive integer.";
            return -1;
        }

        input = d[msg::usrmsg::FLD_INPUT].as<std::string>();
        max_ledger_seq_no = d[msg::usrmsg::FLD_MAX_LEDGER_SEQ_NO].as<uint64_t>();

        return 0;
    }

    /**
     * Extract ledger event subscription request.
     * @param channel Extracted subscription channel.
     * @param enabled Whether the subscription is enabled or not.
     * @param d The json document holding the subscription request.
     *          Accepted message format:
     *          {
     *            "type": "subscription",
     *            "channel": "unl_change" | "ledger_event",
     *            "enabled": true | false
     *          }
     * @return 0 on successful extraction. -1 for failure.
     */
    int extract_subscription_request(usr::NOTIFICATION_CHANNEL &channel, bool &enabled, const jsoncons::json &d)
    {
        if (!d.contains(msg::usrmsg::FLD_CHANNEL) || !d.contains(msg::usrmsg::FLD_ENABLED))
        {
            LOG_DEBUG << "User subscription request required fields missing.";
            return -1;
        }

        if (!d[msg::usrmsg::FLD_CHANNEL].is<std::string>() || !d[msg::usrmsg::FLD_ENABLED].is<bool>())
        {
            LOG_DEBUG << "User subscription request invalid field values.";
            return -1;
        }

        if (d[msg::usrmsg::FLD_CHANNEL] == msg::usrmsg::MSGTYPE_LEDGER_EVENT)
        {
            channel = usr::NOTIFICATION_CHANNEL::LEDGER_EVENT;
        }
        else if (d[msg::usrmsg::FLD_CHANNEL] == msg::usrmsg::MSGTYPE_UNL_CHANGE)
        {
            channel = usr::NOTIFICATION_CHANNEL::UNL_CHANGE;
        }
        else if (d[msg::usrmsg::FLD_CHANNEL] == msg::usrmsg::MSGTYPE_HEALTH_EVENT &&
                 (conf::cfg.health.proposal_stats || conf::cfg.health.connectivity_stats))
        {
            channel = usr::NOTIFICATION_CHANNEL::HEALTH_STAT;
        }
        else
        {
            LOG_DEBUG << "User subscription request invalid channel.";
            return -1;
        }

        enabled = d[msg::usrmsg::FLD_ENABLED].as<bool>();
        return 0;
    }

    /**
     * Extract query information from a ledger query request.
     * @param extracted_query Extracted query criteria.
     * @param extracted_id The query id.
     * @param d The json document holding the query.
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
    int extract_ledger_query(ledger::query::query_request &extracted_query, std::string &extracted_id, const jsoncons::json &d)
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

    bool is_json_string(std::string_view content)
    {
        if (content.empty())
            return true;

        const char first = content[0];
        const char last = content[content.size() - 1];

        if ((first == '\"' && last == '\"') ||
            (first == '{' && last == '}') ||
            (first == '[' && last == ']') ||
            content == STR_TRUE || content == STR_FALSE)
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
            if (node.is_retained)
            {
                // The retained node is serialized as null.
                // This is so the client can identify the self-hash position within the hash tree.
                msg += "null";
            }
            else
            {
                msg += "\"";
                msg += util::to_hex(node.hash);
                msg += "\"";
            }
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

    void populate_ledger_query_results(std::vector<uint8_t> &msg, const std::vector<ledger::ledger_record> &results)
    {
        for (size_t i = 0; i < results.size(); i++)
        {
            const ledger::ledger_record &ledger = results[i];

            msg += "{";
            populate_ledger_fields(msg, ledger);

            // If raw inputs or outputs is not requested, we don't include that field at all in the response.
            // Otherwise the field will always contain an array (empty array if no data).

            if (ledger.inputs)
            {
                msg += SEP_COMMA_NOQUOTE;
                msg += msg::usrmsg::FLD_INPUTS;
                msg += SEP_COLON_NOQUOTE;
                populate_ledger_inputs(msg, *ledger.inputs);
            }

            if (ledger.outputs)
            {
                msg += SEP_COMMA_NOQUOTE;
                msg += msg::usrmsg::FLD_OUTPUTS;
                msg += SEP_COLON_NOQUOTE;
                populate_ledger_outputs(msg, *ledger.outputs);
            }

            msg += (i == (results.size() - 1) ? "}" : "},");
        }
    }

    void populate_ledger_fields(std::vector<uint8_t> &msg, const ledger::ledger_record &ledger)
    {
        msg += "\"";
        msg += msg::usrmsg::FLD_SEQ_NO;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(ledger.seq_no);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_TIMESTAMP;
        msg += SEP_COLON_NOQUOTE;
        msg += std::to_string(ledger.timestamp);
        msg += SEP_COMMA_NOQUOTE;
        msg += msg::usrmsg::FLD_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.ledger_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_PREV_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.prev_ledger_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_STATE_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.state_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_CONFIG_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.config_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_USER_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.user_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_INPUT_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.input_hash);
        msg += SEP_COMMA;
        msg += msg::usrmsg::FLD_OUTPUT_HASH;
        msg += SEP_COLON;
        msg += util::to_hex(ledger.output_hash);
        msg += "\"";
    }

    void populate_ledger_inputs(std::vector<uint8_t> &msg, const std::vector<ledger::ledger_user_input> &inputs)
    {
        msg += "[";
        for (auto itr = inputs.begin(); itr != inputs.end();)
        {
            msg += "{\"";
            msg += msg::usrmsg::FLD_PUBKEY;
            msg += SEP_COLON;
            msg += util::to_hex(itr->pubkey);
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_HASH;
            msg += SEP_COLON;
            msg += util::to_hex(itr->hash);
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_NONCE;
            msg += SEP_COLON_NOQUOTE;
            msg += std::to_string(itr->nonce);
            msg += SEP_COMMA_NOQUOTE;
            msg += msg::usrmsg::FLD_BLOB;
            msg += SEP_COLON;
            msg += util::to_hex(itr->blob);

            itr++;
            msg += (itr == inputs.end() ? "\"}" : "\"},");
        }
        msg += "]";
    }

    void populate_ledger_outputs(std::vector<uint8_t> &msg, const std::vector<ledger::ledger_user_output> &users)
    {
        msg += "[";
        for (auto itr = users.begin(); itr != users.end();)
        {
            msg += "{\"";
            msg += msg::usrmsg::FLD_PUBKEY;
            msg += SEP_COLON;
            msg += util::to_hex(itr->pubkey);
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_HASH;
            msg += SEP_COLON;
            msg += util::to_hex(itr->hash);
            msg += SEP_COMMA;
            msg += msg::usrmsg::FLD_BLOBS;
            msg += "\":[";
            for (auto o_itr = itr->outputs.begin(); o_itr != itr->outputs.end();)
            {
                msg += "\"";
                msg += util::to_hex(*o_itr);

                o_itr++;
                msg += (o_itr == itr->outputs.end() ? "\"" : "\",");
            }

            itr++;
            msg += (itr == users.end() ? "]}" : "]},");
        }
        msg += "]";
    }

} // namespace msg::usrmsg::json