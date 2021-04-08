#ifndef _HP_MSG_USRMSG_PARSER_
#define _HP_MSG_USRMSG_PARSER_

#include "../pchheader.hpp"
#include "../util/util.hpp"
#include "../util/merkle_hash_tree.hpp"
#include "../ledger/ledger_query.hpp"

namespace msg::usrmsg
{
    // Forward declaration
    class usrmsg_parser;

    class usrmsg_parser
    {
        const util::PROTOCOL protocol;
        jsoncons::json jdoc;
        jsoncons::ojson bdoc;

    public:
        usrmsg_parser(const util::PROTOCOL protocol);

        void create_status_response(std::vector<uint8_t> &msg, const uint64_t lcl_seq_no, std::string_view lcl_hash) const;

        void create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                          std::string_view input_hash, const uint64_t ledger_seq_no, const util::h32 &ledger_hash) const;

        void create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content) const;

        void create_contract_output_container(std::vector<uint8_t> &msg, std::string_view hash, const ::std::vector<std::string> &outputs,
                                              const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                              const uint64_t lcl_seq_no, std::string_view lcl_hash) const;

        void create_unl_list_container(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list) const;

        void create_ledger_query_response(std::vector<uint8_t> &msg, std::string_view reply_for,
                                          const ledger::query::query_result &result) const;

        int parse(std::string_view message);

        int extract_type(std::string &extracted_type) const;

        int extract_read_request(std::string &extracted_content) const;

        int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig) const;

        int extract_input_container(std::string &input, std::string &nonce,
                                    uint64_t &max_ledger_seq_no, std::string_view encoded_content) const;

        int extract_ledger_query(ledger::query::query_request &extracted_query, std::string &extracted_id) const;
    };

} // namespace msg::usrmsg

#endif