#ifndef _HP_JSONSCHEMA_USRMSG_HELPERS_H_
#define _HP_JSONSCHEMA_USRMSG_HELPERS_H_

#include <string>

namespace jsonschema::usrmsg
{
void create_user_challenge(std::string &msg, std::string &challengehex);

int verify_user_challenge_response(std::string &extracted_pubkeyhex, std::string_view response, std::string_view original_challenge);
} // namespace jsonschema::usrmsg

#endif