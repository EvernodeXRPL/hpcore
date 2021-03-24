#ifndef _HP_MSG_JSON_USRMSG_JSON_
#define _HP_MSG_JSON_USRMSG_JSON_

#include "../../pchheader.hpp"
#include "../../util/merkle_hash_tree.hpp"
#include "../usrmsg_common.hpp"

namespace msg::usrmsg::json
{

    void create_user_challenge(std::vector<uint8_t> &msg, std::string &challenge);

    void create_server_challenge_response(std::vector<uint8_t> &msg, const std::string &original_challenge);

    void create_status_response(std::vector<uint8_t> &msg, const uint64_t lcl_seq_no, std::string_view lcl_hash);

    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                      std::string_view input_sig);

    void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content);

    void create_contract_output_container(std::vector<uint8_t> &msg, const ::std::vector<std::string_view> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash);

    void create_unl_list_container(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list);

    int verify_user_challenge(std::string &extracted_pubkeyhex, std::string &extracted_protocol, std::string &extracted_server_challenge,
                              std::string_view response, std::string_view original_challenge);

    int parse_user_message(jsoncons::json &d, std::string_view message);

    int extract_type(std::string &extracted_type, const jsoncons::json &d);

    int extract_read_request(std::string &extracted_content, const jsoncons::json &d);

    int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig,
                                       const jsoncons::json &d);

    int extract_input_container(std::string &input, std::string &nonce,
                                uint64_t &max_lcl_seq_no, std::string_view contentjson);

    int extract_ledger_query(ledger_query_request &extracted_query, const jsoncons::json &d);

    bool is_json_string(std::string_view content);

    void populate_output_hash_array(std::vector<uint8_t> &msg, const util::merkle_hash_node &node);

} // namespace msg::usrmsg::json

#endif