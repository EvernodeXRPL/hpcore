#ifndef _HP_MSG_JSON_CONTROLMSG_JSON_
#define _HP_MSG_JSON_CONTROLMSG_JSON_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"

/**
 * Parser helpers for smart contract control messages.
 */
namespace msg::controlmsg::json
{
    int parse_control_message(jsoncons::json &d, std::string_view message);

    int extract_type(std::string &extracted_type, const jsoncons::json &d);

    int extract_peer_changeset(std::vector<p2p::peer_properties> &added_peers, std::vector<p2p::peer_properties> &removed_peers, bool &overwrite, const jsoncons::json &d);

    int extract_peers_from_array(std::vector<p2p::peer_properties> &peers, std::string_view field, const jsoncons::json &d);

} // namespace msg::controlmsg::json

#endif