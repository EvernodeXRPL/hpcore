#ifndef _HP_MSG_BSON_USRMSG_BSON_
#define _HP_MSG_BSON_USRMSG_BSON_

#include "../../pchheader.hpp"
#include "../../util/merkle_hash_tree.hpp"
#include "../../ledger/ledger_query.hpp"

namespace msg::usrmsg::bson
{

    void create_status_response(std::vector<uint8_t> &msg, const uint64_t lcl_seq_no, std::string_view lcl_hash);

    void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                      std::string_view input_hash, const uint64_t ledger_seq_no, const util::h32 &ledger_hash);

    void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content);

    void create_contract_output_container(std::vector<uint8_t> &msg, const ::std::vector<std::string_view> &outputs,
                                          const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                          const uint64_t lcl_seq_no, std::string_view lcl_hash);

    void create_unl_list_container(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list);

    void create_ledger_query_response(std::vector<uint8_t> &msg, std::string_view reply_for,
                                      const ledger::query::query_result &result);

    int verify_user_handshake_response(std::string &extracted_pubkeyhex, std::string &extracted_protocol,
                                       std::string_view response, std::string_view original_challenge);

    int parse_user_message(jsoncons::ojson &d, std::string_view message);

    int extract_type(std::string &extracted_type, const jsoncons::ojson &d);

    int extract_read_request(std::string &extracted_content, const jsoncons::ojson &d);

    int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig,
                                       const jsoncons::ojson &d);

    int extract_input_container(std::string &input, std::string &nonce,
                                uint64_t &max_ledger_seq_no, std::string_view contentbson);

    int extract_ledger_query(ledger::query::query_request &extracted_query, std::string &extracted_id, const jsoncons::ojson &d);

    void populate_output_hash_array(jsoncons::bson::bson_bytes_encoder &encoder, const util::merkle_hash_node &node);

    void populate_ledger_query_results(jsoncons::bson::bson_bytes_encoder &encoder, const std::vector<ledger::query::query_result_record> &results);

    void populate_ledger_blob_map(jsoncons::bson::bson_bytes_encoder &encoder, const ledger::query::blob_map &blob_map);

} // namespace msg::usrmsg::bson

#endif