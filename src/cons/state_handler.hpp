#include "../pchheader.hpp"

namespace cons
{

void send_state_response(p2p::state_request &sr);
void request_state_from_peer(std::string &path, std::string &lcl);

} // namespace cons