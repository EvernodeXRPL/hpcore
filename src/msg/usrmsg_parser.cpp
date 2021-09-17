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

    void usrmsg_parser::create_status_response(std::vector<uint8_t> &msg) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_status_response(msg);
        else
            busrmsg::create_status_response(msg);
    }

    void usrmsg_parser::create_lcl_response(std::vector<uint8_t> &msg) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_lcl_response(msg);
        else
            busrmsg::create_lcl_response(msg);
    }

    void usrmsg_parser::create_contract_input_status(std::vector<uint8_t> &msg, std::string_view status, std::string_view reason,
                                                     std::string_view input_hash, const uint64_t ledger_seq_no, const util::h32 &ledger_hash) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_input_status(msg, status, reason, input_hash, ledger_seq_no, ledger_hash);
        else
            busrmsg::create_contract_input_status(msg, status, reason, input_hash, ledger_seq_no, ledger_hash);
    }

    void usrmsg_parser::create_contract_read_response_container(std::vector<uint8_t> &msg, std::string_view content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_read_response_container(msg, content);
        else
            busrmsg::create_contract_read_response_container(msg, content);
    }

    void usrmsg_parser::create_contract_output_container(std::vector<uint8_t> &msg, std::string_view hash, const ::std::vector<std::string> &outputs,
                                                         const util::merkle_hash_node &hash_root, const std::vector<std::pair<std::string, std::string>> &unl_sig,
                                                         const uint64_t lcl_seq_no, std::string_view lcl_hash) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_contract_output_container(msg, hash, outputs, hash_root, unl_sig, lcl_seq_no, lcl_hash);
        else
            busrmsg::create_contract_output_container(msg, hash, outputs, hash_root, unl_sig, lcl_seq_no, lcl_hash);
    }

    void usrmsg_parser::create_unl_notification(std::vector<uint8_t> &msg, const std::set<std::string> &unl_list) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_unl_notification(msg, unl_list);
        else
            busrmsg::create_unl_notification(msg, unl_list);
    }

    void usrmsg_parser::create_ledger_created_notification(std::vector<uint8_t> &msg, const ledger::ledger_record &ledger) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_ledger_created_notification(msg, ledger);
        else
            busrmsg::create_ledger_created_notification(msg, ledger);
    }

    void usrmsg_parser::create_sync_status_notification(std::vector<uint8_t> &msg, const bool in_sync) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_sync_status_notification(msg, in_sync);
        else
            busrmsg::create_sync_status_notification(msg, in_sync);
    }

    void usrmsg_parser::create_health_notification(std::vector<uint8_t> &msg, const status::health_event &ev) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_health_notification(msg, ev);
        else
            busrmsg::create_health_notification(msg, ev);
    }

    void usrmsg_parser::create_ledger_query_response(std::vector<uint8_t> &msg, std::string_view reply_for,
                                                     const ledger::query::query_result &result) const
    {
        if (protocol == util::PROTOCOL::JSON)
            jusrmsg::create_ledger_query_response(msg, reply_for, result);
        else
            busrmsg::create_ledger_query_response(msg, reply_for, result);
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

    int usrmsg_parser::extract_input_container(std::string &input, uint64_t &nonce,
                                               uint64_t &max_ledger_seq_no, std::string_view encoded_content) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_input_container(input, nonce, max_ledger_seq_no, encoded_content);
        else
            return busrmsg::extract_input_container(input, nonce, max_ledger_seq_no, encoded_content);
    }

    int usrmsg_parser::extract_subscription_request(usr::NOTIFICATION_CHANNEL &channel, bool &enabled)
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_subscription_request(channel, enabled, jdoc);
        else
            return busrmsg::extract_subscription_request(channel, enabled, bdoc);
    }

    int usrmsg_parser::extract_ledger_query(ledger::query::query_request &extracted_query, std::string &extracted_id) const
    {
        if (protocol == util::PROTOCOL::JSON)
            return jusrmsg::extract_ledger_query(extracted_query, extracted_id, jdoc);
        else
            return busrmsg::extract_ledger_query(extracted_query, extracted_id, bdoc);
    }

} // namespace msg::usrmsg