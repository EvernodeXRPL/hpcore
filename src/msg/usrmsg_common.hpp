#ifndef _HP_MSG_USRMSG_COMMON_
#define _HP_MSG_USRMSG_COMMON_

#include "../pchheader.hpp"

namespace msg::usrmsg
{
    // Length of user random challenge bytes.
    constexpr size_t CHALLENGE_LEN = 16;

    // Message field names
    constexpr const char *FLD_HP_VERSION = "hp_version";
    constexpr const char *FLD_TYPE = "type";
    constexpr const char *FLD_SERVER_CHALLENGE = "server_challenge";
    constexpr const char *FLD_CONTRACT_ID = "contract_id";
    constexpr const char *FLD_CONTRACT_VERSION = "contract_version";
    constexpr const char *FLD_CHALLENGE = "challenge";
    constexpr const char *FLD_SIG = "sig";
    constexpr const char *FLD_PUBKEY = "pubkey";
    constexpr const char *FLD_PROTOCOL = "protocol";
    constexpr const char *FLD_UNL = "unl";
    constexpr const char *FLD_INPUT = "input";
    constexpr const char *FLD_INPUT_CONTAINER = "input_container";
    constexpr const char *FLD_INPUT_SIG = "input_sig";
    constexpr const char *FLD_INPUT_HASH = "input_hash";
    constexpr const char *FLD_LEDGER_SEQ_NO = "ledger_seq_no";
    constexpr const char *FLD_LEDGER_HASH = "ledger_hash";
    constexpr const char *FLD_MAX_LEDGER_SEQ_NO = "max_ledger_seq_no";
    constexpr const char *FLD_CONTENT = "content";
    constexpr const char *FLD_OUTPUTS = "outputs";
    constexpr const char *FLD_OUTPUT_HASH = "output_hash";
    constexpr const char *FLD_HASH_TREE = "hash_tree";
    constexpr const char *FLD_UNL_SIG = "unl_sig";
    constexpr const char *FLD_NONCE = "nonce";
    constexpr const char *FLD_STATUS = "status";
    constexpr const char *FLD_REASON = "reason";
    constexpr const char *FLD_ROUND_TIME = "round_time";
    constexpr const char *FLD_CONTARCT_EXECUTION_ENABLED = "contract_execution_enabled";
    constexpr const char *FLD_READ_REQUESTS_ENABLED = "read_requests_enabled";
    constexpr const char *FLD_IS_FULL_HISTORY_NODE = "is_full_history_node";
    constexpr const char *FLD_CURRENT_UNL = "current_unl";
    constexpr const char *FLD_PEERS = "peers";
    constexpr const char *FLD_ID = "id";
    constexpr const char *FLD_REPLY_FOR = "reply_for";
    constexpr const char *FLD_FILTER_BY = "filter_by";
    constexpr const char *FLD_INCLUDE = "include";
    constexpr const char *FLD_PARAMS = "params";
    constexpr const char *FLD_SEQ_NO = "seq_no";
    constexpr const char *FLD_ERROR = "error";
    constexpr const char *FLD_RESULTS = "results";
    constexpr const char *FLD_TIMESTAMP = "timestamp";
    constexpr const char *FLD_HASH = "hash";
    constexpr const char *FLD_PREV_HASH = "prev_hash";
    constexpr const char *FLD_STATE_HASH = "state_hash";
    constexpr const char *FLD_CONFIG_HASH = "config_hash";
    constexpr const char *FLD_USER_HASH = "user_hash";
    constexpr const char *FLD_INPUTS = "inputs";
    constexpr const char *FLD_BLOB = "blob";
    constexpr const char *FLD_BLOBS = "blobs";

    // Message types
    constexpr const char *MSGTYPE_USER_CHALLENGE = "user_challenge";
    constexpr const char *MSGTYPE_USER_CHALLENGE_RESPONSE = "user_challenge_response";
    constexpr const char *MSGTYPE_SERVER_CHALLENGE_RESPONSE = "server_challenge_response";
    constexpr const char *MSGTYPE_CONTRACT_READ_REQUEST = "contract_read_request";
    constexpr const char *MSGTYPE_CONTRACT_READ_RESPONSE = "contract_read_response";
    constexpr const char *MSGTYPE_CONTRACT_INPUT = "contract_input";
    constexpr const char *MSGTYPE_CONTRACT_INPUT_STATUS = "contract_input_status";
    constexpr const char *MSGTYPE_CONTRACT_OUTPUT = "contract_output";
    constexpr const char *MSGTYPE_STAT = "stat";
    constexpr const char *MSGTYPE_STAT_RESPONSE = "stat_response";
    constexpr const char *MSGTYPE_UNL_CHANGE = "unl_change";
    constexpr const char *MSGTYPE_LEDGER_QUERY = "ledger_query";
    constexpr const char *MSGTYPE_LEDGER_QUERY_RESULT = "ledger_query_result";
    constexpr const char *MSGTYPE_UNKNOWN = "unknown";

    // Values
    constexpr const char *STATUS_ACCEPTED = "accepted";
    constexpr const char *STATUS_REJECTED = "rejected";
    constexpr const char *REASON_BAD_MSG_FORMAT = "bad_msg_format";
    constexpr const char *REASON_INVALID_MSG_TYPE = "invalid_msg_type";
    constexpr const char *REASON_BAD_SIG = "bad_sig";
    constexpr const char *REASON_APPBILL_BALANCE_EXCEEDED = "appbill_balance_exceeded";
    constexpr const char *REASON_MAX_LEDGER_EXPIRED = "max_ledger_expired";
    constexpr const char *REASON_MAX_LEDGER_OFFSET_EXCEEDED = "max_ledger_offset_exceeded";
    constexpr const char *REASON_NONCE_EXPIRED = "nonce_expired";
    constexpr const char *REASON_ALREADY_SUBMITTED = "already_submitted";
    constexpr const char *REASON_NONCE_OVERFLOW = "nonce_overflow";
    constexpr const char *REASON_ROUND_INPUTS_OVERFLOW = "round_inputs_overflow";
    constexpr const char *QUERY_FILTER_BY_SEQ_NO = "seq_no";

} // namespace msg::usrmsg

#endif