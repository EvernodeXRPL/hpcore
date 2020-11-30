#ifndef _HP_MSG_JSON_CONTROLMSG_JSON_
#define _HP_MSG_JSON_CONTROLMSG_JSON_

#include "../../pchheader.hpp"

/**
 * Parser helpers for smart contract control messages.
 */
namespace msg::controlmsg::json
{
    int parse_control_message(jsoncons::json &d, std::string_view message);

    int extract_type(std::string &extracted_type, const jsoncons::json &d);

    int extract_unl_changeset(std::vector<std::string> &additions, std::vector<std::string> &removals, const jsoncons::json &d, const bool convert_to_bin);

    void extract_string_array(std::vector<std::string> &vec, const jsoncons::json &d, const char *field_name, const bool convert_to_bin);

} // namespace msg::controlmsg::json

#endif