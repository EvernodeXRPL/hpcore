#include "../pchheader.hpp"
#include "../util.hpp"
#include "json/usrmsg_json.hpp"
#include "bson/usrmsg_bson.hpp"
#include "usrmsg_parser.hpp"

namespace jusrmsg = msg::usrmsg::json;
namespace busrmsg = msg::usrmsg::bson;

namespace msg::usrmsg
{
    usrmsg_parser::usrmsg_parser(const util::PROTOCOL protocol) : protocol(protocol)
    {
    }

    void usrmsg_parser::create_status_response(std::vector<uint8_t> &msg) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_status_response(msg);
        else
            busrmsg::create_status_response(msg);
    }

    void usrmsg_parser::create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status,
                                                     std::string_view reason, std::string_view input_sig) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_input_status(msg, status, reason, input_sig);
        else
            ;
    }

    void usrmsg_parser::create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_read_response_container(msg, content);
        else
            ;
    }

    void usrmsg_parser::create_contract_output_container(std::vector<uint8_t> &msg, std::string_view content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_output_container(msg, content);
        else
            ;
    }

    int usrmsg_parser::parse(std::string_view message)
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::parse_user_message(jsonDoc, message);
        else
            return -1;
    }

    int usrmsg_parser::extract_type(std::string &extracted_type) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_type(extracted_type, jsonDoc);
        else
            return -1;
    }

    int usrmsg_parser::extract_read_request(std::string &extracted_content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_read_request(extracted_content, jsonDoc);
        else
            return -1;
    }

    int usrmsg_parser::extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_signed_input_container(extracted_input_container, extracted_sig, jsonDoc);
        else
            return -1;
    }

    int usrmsg_parser::extract_input_container(std::string &input, std::string &nonce,
                                               uint64_t &max_lcl_seqno, std::string_view encoded_content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_input_container(input, nonce, max_lcl_seqno, encoded_content);
        else
            return -1;
    }

} // namespace msg::usrmsg