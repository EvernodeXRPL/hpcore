#include "../../pchheader.hpp"
#include "../controlmsg_common.hpp"
#include "controlmsg_json.hpp"

namespace msg::controlmsg::json
{
    // JSON separators
    constexpr const char *SEP_COMMA = "\",\"";
    constexpr const char *SEP_COLON = "\":\"";
    constexpr const char *SEP_COMMA_NOQUOTE = ",\"";
    constexpr const char *SEP_COLON_NOQUOTE = "\":";

    // Message types
    constexpr const char *MSGTYPE_HANDSHAKE_CHALLENGE = "handshake_challenge";

    /**
     * Parses a json control message sent by the contract.
     * @param d Jsoncons document to which the parsed json should be loaded.
     * @param message The message to parse.
     *                Accepted message format:
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
            LOG_DEBUG << "User json message parsing failed.";
            return -1;
        }

        // Check existence of msg type field.
        if (!d.contains(msg::controlmsg::FLD_TYPE) || !d[msg::controlmsg::FLD_TYPE].is<std::string>())
        {
            LOG_DEBUG << "User json message 'type' missing or invalid.";
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

} // namespace msg::controlmsg::json