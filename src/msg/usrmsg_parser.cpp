#include "../pchheader.hpp"
#include "../util/util.hpp"
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

    void usrmsg_parser::create_status_response(std::vector<uint8_t> &msg, const uint64_t lcl_seq_no, std::string_view lcl) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_status_response(msg, lcl_seq_no, lcl);
        else
            busrmsg::create_status_response(msg, lcl_seq_no, lcl);
    }

    void usrmsg_parser::create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status,
                                                     std::string_view reason, std::string_view input_sig) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_input_status(msg, status, reason, input_sig);
        else
            busrmsg::create_contract_input_status(msg, status, reason, input_sig);
    }

    void usrmsg_parser::create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_read_response_container(msg, content);
        else
            busrmsg::create_contract_read_response_container(msg, content);
    }

    void usrmsg_parser::create_contract_output_container(std::vector<uint8_t> &msg, const ::std::vector<std::string_view> &outputs,
                                                         const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                                         const uint64_t lcl_seq_no, std::string_view lcl) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_output_container(msg, outputs, hash_root, unl_sig, lcl_seq_no, lcl);
        else
            busrmsg::create_contract_output_container(msg, outputs, hash_root, unl_sig, lcl_seq_no, lcl);
    }

    void usrmsg_parser::create_changed_unl_container(std::vector<uint8_t> &msg, const ::std::set<std::string> &unl_list) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_changed_unl_container(msg, unl_list);
        else
            busrmsg::create_changed_unl_container(msg, unl_list);
    }

    int usrmsg_parser::parse(std::string_view message)
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::parse_user_message(jdoc, message);
        else
            return busrmsg::parse_user_message(bdoc, message);
    }

    int usrmsg_parser::extract_type(std::string &extracted_type) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_type(extracted_type, jdoc);
        else
            return busrmsg::extract_type(extracted_type, bdoc);
    }

    int usrmsg_parser::extract_read_request(std::string &extracted_content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_read_request(extracted_content, jdoc);
        else
            return busrmsg::extract_read_request(extracted_content, bdoc);
    }

    int usrmsg_parser::extract_signed_input_container(std::string &extracted_input_container, std::string &extracted_sig) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_signed_input_container(extracted_input_container, extracted_sig, jdoc);
        else
            return busrmsg::extract_signed_input_container(extracted_input_container, extracted_sig, bdoc);
    }

    int usrmsg_parser::extract_input_container(std::string &input, std::string &nonce,
                                               uint64_t &max_lcl_seqno, std::string_view encoded_content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_input_container(input, nonce, max_lcl_seqno, encoded_content);
        else
            return busrmsg::extract_input_container(input, nonce, max_lcl_seqno, encoded_content);
    }

} // namespace msg::usrmsg