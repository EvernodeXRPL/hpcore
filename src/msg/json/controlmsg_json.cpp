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
     * Extracts unl additions and removals from the json document.
     * Format:
     * {
     *   "type": "unl_changeset",
     *   "add": ["pk1","pk2",...]
     *   "remove": ["pk1","pk2",...]
     * }
     */
    int extract_unl_changeset(std::vector<std::string> &additions, std::vector<std::string> &removals, const jsoncons::json &d)
    {
        extract_string_array(additions, d, FLD_ADD);
        extract_string_array(removals, d, FLD_REMOVE);
        return 0;
    }

    void extract_string_array(std::vector<std::string> &vec, const jsoncons::json &d, const char *field_name)
    {
        if (!d.contains(field_name) || !d[field_name].is_array())
            return;

        for (const auto &v : d[field_name].array_range())
        {
            std::string hex_pubkey = "ed" + v.as<std::string>();

            std::string bin_pubkey;
            bin_pubkey.resize(crypto::PFXD_PUBKEY_BYTES);
            if (util::hex2bin(
                    reinterpret_cast<unsigned char *>(bin_pubkey.data()),
                    bin_pubkey.length(),
                    hex_pubkey) != -1)
            {
                vec.push_back(bin_pubkey);
            }
        }
    }

} // namespace msg::controlmsg::json