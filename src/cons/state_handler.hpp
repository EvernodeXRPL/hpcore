#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

namespace cons
{

std::list<std::string> candidate_state_responses;

void send_state_response(p2p::state_request &sr);

void request_state_from_peer(std::string &path, std::string &lcl);

} // namespace cons