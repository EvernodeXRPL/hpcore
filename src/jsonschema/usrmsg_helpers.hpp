#ifndef _HP_JSONSCHEMA_USRMSG_HELPERS_
#define _HP_JSONSCHEMA_USRMSG_HELPERS_

#include "../pchheader.hpp"

namespace jsonschema::usrmsg
{

// Message field names exposed out of this namespace.
extern const char* const FLD_TYPE;

// Message types
const char* const MSGTYPE_CHALLENGE = "public_challenge";
const char* const MSGTYPE_CHALLENGE_RESP = "challenge_resp";
const char* const MSGTYPE_CONTRACT_INPUT = "contract_input";
const char* const MSGTYPE_STAT = "stat";
const char* const MSGTYPE_STAT_RESP = "stat_resp";

void create_user_challenge(std::string &msg, std::string &challengehex);

void create_status_response(std::string &msg);

int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge);

int extract_signed_input_container(std::string &extracted_content, std::string &extracted_sig, const rapidjson::Document &d);

int extract_input_container(std::string &nonce, std::string &input, uint64_t &max_ledger_seqno, std::string_view contentjson);

int parse_user_message(rapidjson::Document &d, std::string_view message);

} // namespace jsonschema::usrmsg

#endif