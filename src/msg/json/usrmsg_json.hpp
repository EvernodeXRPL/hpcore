#ifndef _HP_MSG_JSON_USRMSG_JSON_
#define _HP_MSG_JSON_USRMSG_JSON_

#include "../../pchheader.hpp"

namespace msg::usrmsg::json
{

    void create_user_challenge(std::string &msg, std::string &challengehex);

    void create_status_response(std::string &msg);

    void create_contract_input_status(std::string &msg, std::string_view status, std::string_view reason, std::string_view input_sig);

    void create_contract_read_response_container(std::string &msg, std::string_view content);

    void create_contract_output_container(std::string &msg, std::string_view content);

    int verify_user_handshake_response(std::string &extracted_pubkeyhex, std::string &extracted_protocol,
                                       std::string_view response, std::string_view original_challenge);

    int extract_read_request(std::string &extracted_content, const rapidjson::Document &d);

    int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig, const rapidjson::Document &d);

    int extract_input_container(std::string &input, std::string &nonce, uint64_t &max_lcl_seqno, std::string_view contentjson);

    int parse_user_message(rapidjson::Document &d, std::string_view message);

} // namespace msg::usrmsg::json

#endif