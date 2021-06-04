#ifndef _HP_MSG_JSON_USRMSG_JSON_
#define _HP_MSG_JSON_USRMSG_JSON_

#include "../../pchheader.hpp"
#include "../../util/merkle_hash_tree.hpp"
#include "../../ledger/ledger_query.hpp"

namespace msg::usrmsg::json
{

    void create_user_challenge(std::vector<uint8_t> &msg, std::string &challenge);

    void create_lcl_response(std::vector<uint8_t> &msg);

    void create_server_challenge_response(std::vector<uint8_t> &msg, const std::string &original_challenge);

    void create_status_response(std::vector<uint8_t> &msg);

    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                      std::string_view input_hash, const uint64_t ledger_seq_no, const util::h32 &ledger_hash);

    void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content);

    void create_contract_output_container(std::vector<uint8_t> &msg, std::string_view hash, const ::std::vector<std::string> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash);

    void create_unl_notification(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list);

    void create_sync_status_notification(std::vector<uint8_t> &msg, const bool in_sync);

    void create_ledger_query_response(std::vector<uint8_t> &msg, std::string_view reply_for,
                                      const ledger::query::query_result &result);

    int verify_user_challenge(std::string &extracted_pubkeyhex, std::string &extracted_protocol, std::string &extracted_server_challenge,
                              std::string_view response, std::string_view original_challenge);

    int parse_user_message(jsoncons::json &d, std::string_view message);

    int extract_type(std::string &extracted_type, const jsoncons::json &d);

    int extract_read_request(std::string &extracted_content, const jsoncons::json &d);

    int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig,
                                       const jsoncons::json &d);

    int extract_input_container(std::string &input, uint64_t &nonce,
                                uint64_t &max_ledger_seq_no, std::string_view contentjson);

    int extract_ledger_query(ledger::query::query_request &extracted_query, std::string &extracted_id, const jsoncons::json &d);

    bool is_json_string(std::string_view content);

    void populate_output_hash_array(std::vector<uint8_t> &msg, const util::merkle_hash_node &node);

    void populate_ledger_query_results(std::vector<uint8_t> &msg, const std::vector<ledger::ledger_record> &results);

    void populate_ledger_inputs(std::vector<uint8_t> &msg, const std::vector<ledger::ledger_user_input> &inputs);

    void populate_ledger_outputs(std::vector<uint8_t> &msg, const std::vector<ledger::ledger_user_output> &users);

} // namespace msg::usrmsg::json

#endif