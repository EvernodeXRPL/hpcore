#ifndef _HP_JSONSCHEMA_USRMSG_HELPERS_
#define _HP_JSONSCHEMA_USRMSG_HELPERS_

#include "../pchheader.hpp"

namespace jsonschema::usrmsg
{

// Message field names exposed out of this namespace.
extern const char* const FLD_TYPE;

// Message types
constexpr const char* MSGTYPE_HANDSHAKE_CHALLENGE = "handshake_challenge";
constexpr const char* MSGTYPE_HANDSHAKE_RESPONSE = "handshake_response";
constexpr const char* MSGTYPE_CONTRACT_READ_REQUEST = "contract_read_request";
constexpr const char* MSGTYPE_CONTRACT_READ_RESPONSE = "contract_read_response";
constexpr const char* MSGTYPE_CONTRACT_INPUT = "contract_input";
constexpr const char* MSGTYPE_CONTRACT_INPUT_STATUS = "contract_input_status";
constexpr const char* MSGTYPE_CONTRACT_OUTPUT = "contract_output";
constexpr const char* MSGTYPE_STAT = "stat";
constexpr const char* MSGTYPE_STAT_RESPONSE = "stat_response";
constexpr const char* MSGTYPE_UNKNOWN = "unknown";

constexpr const char *STATUS_ACCEPTED = "accepted";
constexpr const char *STATUS_REJECTED = "rejected";
constexpr const char *REASON_BAD_MSG_FORMAT = "bad_msg_format";
constexpr const char *REASON_INVALID_MSG_TYPE = "invalid_msg_type";
constexpr const char *REASON_DUPLICATE_MSG = "dup_msg";
constexpr const char *REASON_BAD_SIG = "bad_sig";
constexpr const char *REASON_APPBILL_BALANCE_EXCEEDED = "appbill_balance_exceeded";
constexpr const char *REASON_MAX_LEDGER_EXPIRED = "max_ledger_expired";

void create_user_challenge(std::string &msg, std::string &challengehex);

void create_status_response(std::string &msg);

void create_contract_input_status(std::string &msg, std::string_view status, std::string_view reason, std::string_view input_sig);

void create_contract_read_response_container(std::string &msg, std::string_view content);

void create_contract_output_container(std::string &msg, std::string_view content);

int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge);

int extract_read_request(std::string &extracted_content, const rapidjson::Document &d);

int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig, const rapidjson::Document &d);

int extract_input_container(std::string &input, std::string &nonce, uint64_t &max_lcl_seqno, std::string_view contentjson);

int parse_user_message(rapidjson::Document &d, std::string_view message);

} // namespace jsonschema::usrmsg

#endif