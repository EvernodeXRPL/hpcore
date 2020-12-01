#ifndef _HP_MSG_USRMSG_COMMON_
#define _HP_MSG_USRMSG_COMMON_

#include "../pchheader.hpp"

namespace msg::usrmsg
{
    // Length of user random challenge bytes.
    constexpr size_t CHALLENGE_LEN = 16;

    // Message field names
    constexpr const char *FLD_TYPE = "type";
    constexpr const char *FLD_CONTRACT_ID = "contract_id";
    constexpr const char *FLD_CHALLENGE = "challenge";
    constexpr const char *FLD_SIG = "sig";
    constexpr const char *FLD_PUBKEY = "pubkey";
    constexpr const char *FLD_PROTOCOL = "protocol";
    constexpr const char *FLD_INPUT = "input";
    constexpr const char *FLD_INPUT_CONTAINER = "input_container";
    constexpr const char *FLD_INPUT_SIG = "input_sig";
    constexpr const char *FLD_MAX_LCL_SEQ = "max_lcl_seqno";
    constexpr const char *FLD_CONTENT = "content";
    constexpr const char *FLD_NONCE = "nonce";
    constexpr const char *FLD_LCL = "lcl";
    constexpr const char *FLD_LCL_SEQ = "lcl_seqno";
    constexpr const char *FLD_STATUS = "status";
    constexpr const char *FLD_REASON = "reason";

    // Message types
    constexpr const char *MSGTYPE_HANDSHAKE_CHALLENGE = "handshake_challenge";
    constexpr const char *MSGTYPE_HANDSHAKE_RESPONSE = "handshake_response";
    constexpr const char *MSGTYPE_CONTRACT_READ_REQUEST = "contract_read_request";
    constexpr const char *MSGTYPE_CONTRACT_READ_RESPONSE = "contract_read_response";
    constexpr const char *MSGTYPE_CONTRACT_INPUT = "contract_input";
    constexpr const char *MSGTYPE_CONTRACT_INPUT_STATUS = "contract_input_status";
    constexpr const char *MSGTYPE_CONTRACT_OUTPUT = "contract_output";
    constexpr const char *MSGTYPE_STAT = "stat";
    constexpr const char *MSGTYPE_STAT_RESPONSE = "stat_response";
    constexpr const char *MSGTYPE_UNKNOWN = "unknown";

    // Values
    constexpr const char *STATUS_ACCEPTED = "accepted";
    constexpr const char *STATUS_REJECTED = "rejected";
    constexpr const char *REASON_BAD_MSG_FORMAT = "bad_msg_format";
    constexpr const char *REASON_INVALID_MSG_TYPE = "invalid_msg_type";
    constexpr const char *REASON_BAD_SIG = "bad_sig";
    constexpr const char *REASON_APPBILL_BALANCE_EXCEEDED = "appbill_balance_exceeded";
    constexpr const char *REASON_MAX_LEDGER_EXPIRED = "max_ledger_expired";
    constexpr const char *REASON_NONCE_EXPIRED = "nonce_expired";
    constexpr const char *REASON_ALREADY_SUBMITTED = "already_submitted";

} // namespace msg::usrmsg

#endif