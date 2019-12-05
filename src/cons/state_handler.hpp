#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

namespace cons
{

extern std::list<std::string> candidate_state_responses;

p2p::peer_outbound_message send_state_response(const p2p::state_request &sr);

void request_state_from_peer(const std::string &path, bool is_file, std::string &lcl, int32_t block_id);

void reset_state_sync();

int handle_state_response();

} // namespace cons