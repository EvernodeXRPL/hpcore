#include "../pchheader.hpp"
#include "json/controlmsg_json.hpp"
#include "controlmsg_parser.hpp"

namespace jctlmsg = msg::controlmsg::json;

namespace msg::controlmsg
{
    int controlmsg_parser::parse(std::string_view message)
    {
        return jctlmsg::parse_control_message(jsonDoc, message);
    }

    int controlmsg_parser::extract_type(std::string &extracted_type) const
    {
        return jctlmsg::extract_type(extracted_type, jsonDoc);
    }

} // namespace msg::controlmsg