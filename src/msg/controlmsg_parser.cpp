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

    int controlmsg_parser::extract_peer_changeset(std::vector<p2p::peer_properties> &added_peers, std::vector<p2p::peer_properties> &removed_peers, bool &overwrite) const
    {
        return jctlmsg::extract_peer_changeset(added_peers, removed_peers, overwrite, jdoc);
    }

} // namespace msg::controlmsg