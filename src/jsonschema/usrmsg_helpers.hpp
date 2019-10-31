#ifndef _HP_JSONSCHEMA_USRMSG_HELPERS_H_
#define _HP_JSONSCHEMA_USRMSG_HELPERS_H_

#include <string>
#include <rapidjson/document.h>

namespace jsonschema::usrmsg
{

static const char *SCHEMA_VERSION = "0.1";

// These fields are used on json messages response validation.
static const char *FLD_VERSION = "version";
static const char *FLD_TYPE = "type";
static const char *FLD_CHALLENGE = "challenge";
static const char *FLD_SIG = "sig";
static const char *FLD_PUBKEY = "pubkey";
static const char *FLD_INPUT = "input";
static const char *FLD_MAX_LGR_SEQ = "maxledgerseqno";
static const char *FLD_CONTENT = "content";
static const char *FLD_NONCE = "nonce";

// Message types
static const char *MSGTYPE_CHALLENGE = "public_challenge";
static const char *MSGTYPE_CHALLENGE_RESP = "challenge_response";
static const char *MSGTYPE_CONTRACT_INPUT = "contract_input";

void create_user_challenge(std::string &msg, std::string &challengehex);

int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge);

int verify_signed_input_container(std::string &extracted_content, const rapidjson::Document &d, std::string_view pubkey);

int extract_input_container(std::string &nonce, std::string &input, uint64_t &max_ledger_seqno, std::string_view contentjson);

int parse_user_message(rapidjson::Document &d, std::string_view message);

} // namespace jsonschema::usrmsg

#endif