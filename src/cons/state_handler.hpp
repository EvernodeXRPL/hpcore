#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

namespace cons
{

std::list<std::string> candidate_state_responses;

p2p::peer_outbound_message send_state_response(p2p::state_request &sr);

void request_state_from_peer(const std::string &path, bool is_file, std::string &lcl, int32_t block_id = -1);

} // namespace cons