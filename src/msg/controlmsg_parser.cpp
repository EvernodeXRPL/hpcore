#include "../pchheader.hpp"
#include "json/controlmsg_json.hpp"
#include "controlmsg_parser.hpp"

namespace jctlmsg = msg::controlmsg::json;

namespace msg::controlmsg
{
    int controlmsg_parser::parse(std::string_view message)
    {
        return jctlmsg::parse_control_message(jdoc, message);
    }

    int controlmsg_parser::extract_type(std::string &extracted_type) const
    {
        return jctlmsg::extract_type(extracted_type, jdoc);
    }

    int controlmsg_parser::extract_unl_changeset(std::vector<std::string> &additions, std::vector<std::string> &removals, const bool convert_to_bin)
    {
        return jctlmsg::extract_unl_changeset(additions, removals, jdoc, convert_to_bin);
    }

} // namespace msg::controlmsg