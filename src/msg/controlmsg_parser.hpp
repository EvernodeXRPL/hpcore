#ifndef _HP_MSG_CONTROLMSG_PARSER_
#define _HP_MSG_CONTROLMSG_PARSER_

#include "../pchheader.hpp"

namespace msg::controlmsg
{
    class controlmsg_parser
    {
        jsoncons::json jsonDoc;

    public:
        int parse(std::string_view message);

        int extract_type(std::string &extracted_type) const;
    };

} // namespace msg::controlmsg

#endif