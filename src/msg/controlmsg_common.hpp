#ifndef _HP_MSG_CONTROLMSG_COMMON_
#define _HP_MSG_CONTROLMSG_COMMON_

#include "../pchheader.hpp"

namespace msg::controlmsg
{
    // Message field names
    constexpr const char *FLD_TYPE = "type";
    constexpr const char *FLD_ADD = "add";
    constexpr const char *FLD_REMOVE = "remove";

    // Message types
    constexpr const char *MSGTYPE_PEER_CHANGESET = "peer_changeset";

} // namespace msg::controlmsg

#endif