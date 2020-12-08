#ifndef _HP_MSG_CONTROLMSG_PARSER_
#define _HP_MSG_CONTROLMSG_PARSER_

#include "../pchheader.hpp"

namespace msg::controlmsg
{
    class controlmsg_parser
    {
        jsoncons::json jdoc;

    public:
        int parse(std::string_view message);
        int extract_type(std::string &extracted_type) const;
        int extract_unl_changeset(std::set<std::string> &additions, std::set<std::string> &removals);
    };

} // namespace msg::controlmsg

#endif