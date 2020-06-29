#ifndef _HP_MSG_USRMSG_PARSER_
#define _HP_MSG_USRMSG_PARSER_

#include "bson/microbson.hpp"
#include "../util.hpp"
#include "../pchheader.hpp"

namespace msg::usrmsg
{
    // Forward declaration
    class usrmsg_parser;

    class usrmsg_parser
    {
        const util::PROTOCOL protocol;
        rapidjson::Document jsonDoc;
        microbson::document bsonDoc;

    public:
        usrmsg_parser(const util::PROTOCOL protocol);

        void create_status_response(std::string &msg) const;

        void create_contract_input_status(std::string &msg, std::string_view status,
                                          std::string_view reason, std::string_view input_sig) const;

        void create_contract_read_response_container(std::string &msg, std::string_view content) const;

        void create_contract_output_container(std::string &msg, std::string_view content) const;

        int parse(std::string_view message);

        int extract_type(std::string &extracted_type) const;

        int extract_read_request(std::string &extracted_content) const;

        int extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig) const;

        int extract_input_container(std::string &input, std::string &nonce,
                                    uint64_t &max_lcl_seqno, std::string_view encoded_content) const;
    };

} // namespace msg::usrmsg

#endif