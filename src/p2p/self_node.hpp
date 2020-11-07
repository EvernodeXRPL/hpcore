#ifndef _HP_P2P_SELF_NODE_
#define _HP_P2P_SELF_NODE_

#include "../pchheader.hpp"

namespace p2p::self
{
    void process_next_message();
    void send(std::string_view message);

} // namespace p2p
#endif