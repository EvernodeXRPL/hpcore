#ifndef _HP_MSG_CONTROLMSG_PARSER_
#define _HP_MSG_CONTROLMSG_PARSER_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

namespace msg::controlmsg
{
    class controlmsg_parser
    {
        jsoncons::json jdoc;

    public:
        int parse(std::string_view message);
        int extract_type(std::string &extracted_type) const;
        int extract_peer_changeset(std::vector<p2p::peer_properties> &added_peers, std::vector<p2p::peer_properties> &removed_peers) const;
    };

} // namespace msg::controlmsg

#endif