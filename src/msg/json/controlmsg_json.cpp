#include "../../pchheader.hpp"
#include "../../util/util.hpp"
#include "../../crypto.hpp"
#include "../controlmsg_common.hpp"
#include "controlmsg_json.hpp"

namespace msg::controlmsg::json
{
    // JSON separators
    constexpr const char *SEP_COMMA = "\",\"";
    constexpr const char *SEP_COLON = "\":\"";
    constexpr const char *SEP_COMMA_NOQUOTE = ",\"";
    constexpr const char *SEP_COLON_NOQUOTE = "\":";

    /**
     * Parses a json control message sent by the contract.
     * @param d Jsoncons document to which the parsed json should be loaded.
     * @param message The message to parse.
     *                Message format:
     *                {
     *                  'type': '<message type>'
     *                  ...
     *                }
     * @return 0 on successful parsing. -1 for failure.
     */
    int parse_control_message(jsoncons::json &d, std::string_view message)
    {
        try
        {
            d = jsoncons::json::parse(message, jsoncons::strict_json_parsing());
        }
        catch (const std::exception &e)
        {
            LOG_ERROR << "Control json message parsing failed. " << e.what();
            return -1;
        }

        // Check existence of msg type field.
        if (!d.contains(msg::controlmsg::FLD_TYPE) || !d[msg::controlmsg::FLD_TYPE].is<std::string>())
        {
            LOG_ERROR << "Control json message 'type' missing or invalid.";
            return -1;
        }

        return 0;
    }

    /**
     * Extracts the message 'type' value from the json document.
     */
    int extract_type(std::string &extracted_type, const jsoncons::json &d)
    {
        extracted_type = d[msg::controlmsg::FLD_TYPE].as<std::string>();
        return 0;
    }

    /**
     * Extracts the peer changes from a peer changeset message.
     * Message format:
     * {
     *   'type': 'peer_changeset',
     *   'add': ['<ip1>','<ip2>', ...],
     *   'remove': ['<ip1>','<ip2>', ...]
     * }
     */
    int extract_peer_changeset(std::vector<p2p::peer_properties> &added_peers, std::vector<p2p::peer_properties> &removed_peers, const jsoncons::json &d)
    {
        if (extract_peers_from_array(added_peers, msg::controlmsg::FLD_ADD, d) == -1 ||
            extract_peers_from_array(removed_peers, msg::controlmsg::FLD_REMOVE, d) == -1)
            return -1;

        return 0;
    }

    int extract_peers_from_array(std::vector<p2p::peer_properties> &peers, std::string_view field, const jsoncons::json &d)
    {
        if (d.contains(field))
        {
            if (!d[field].is_array())
            {
                LOG_ERROR << "Extract peers: Invalid array field: " << field;
                return -1;
            }

            for (auto &peer : d[field].array_range())
            {
                if (!peer.is<std::string>())
                {
                    LOG_ERROR << "Extract peers: Invalid peer entry in field: " << field;
                    return -1;
                }

                conf::peer_ip_port ipp;
                if (ipp.from_string(peer.as<std::string_view>()) == -1)
                {
                    LOG_ERROR << "Extract peers: Invalid peer format in field: " << field;
                    return -1;
                }

                peers.push_back(p2p::peer_properties{ipp, -1, 0, 0});
            }
        }

        return 0;
    }

} // namespace msg::controlmsg::json