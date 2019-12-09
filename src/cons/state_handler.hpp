#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

namespace cons
{

extern std::list<std::string> candidate_state_responses;

int create_state_response(p2p::peer_outbound_message &msg, const p2p::state_request &sr);

void request_state_from_peer(const std::string &path, const bool is_file, const std::string &lcl, const int32_t block_id, const hasher::B2H expected_hash);

void start_state_sync(const hasher::B2H state_hash_to_request);

int handle_state_response();

} // namespace cons