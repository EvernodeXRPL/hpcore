#ifndef _HP_JSONSCHEMA_USRMSG_HELPERS_
#define _HP_JSONSCHEMA_USRMSG_HELPERS_

#include "../pchheader.hpp"

namespace jsonschema::usrmsg
{

// Message field names exposed out of this namespace.
extern const char* const FLD_TYPE;

// Message types
constexpr const char* MSGTYPE_CHALLENGE = "public_challenge";
constexpr const char* MSGTYPE_CHALLENGE_RESP = "challenge_resp";
constexpr const char* MSGTYPE_CONTRACT_INPUT = "contract_input";
constexpr const char* MSGTYPE_CONTRACT_OUTPUT = "contract_output";
constexpr const char* MSGTYPE_STAT = "stat";
constexpr const char* MSGTYPE_STAT_RESP = "stat_resp";

void create_user_challenge(std::string &msg, std::string &challengehex);

void create_status_response(std::string &msg);

void create_contract_output_container(std::string &msg, std::string_view content);

int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge);

int extract_signed_input_container(std::string &extracted_content, std::string &extracted_sig, const rapidjson::Document &d);

int extract_input_container(std::string &nonce, std::string &input, uint64_t &max_ledger_seqno, std::string_view contentjson);

int parse_user_message(rapidjson::Document &d, std::string_view message);

} // namespace jsonschema::usrmsg

#endif