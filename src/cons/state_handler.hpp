#ifndef _HP_CONS_STATE_HANDLER_
#define _HP_CONS_STATE_HANDLER_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../statefs/hasher.hpp"

namespace cons
{

enum BACKLOG_ITEM_TYPE
{
    DIR = 0,
    FILE = 1,
    BLOCK = 2
};

// Represents a queued up state sync operation which needs to be performed.
struct backlog_item
{
    BACKLOG_ITEM_TYPE type;
    std::string path;
    int32_t block_id = -1; // Only relevant if type=BLOCK
    hasher::B2H expected_hash;

    // No. of cycles that this item has been waiting in pending state.
    // Used by pending_responses list to increase wait count.
    int16_t waiting_cycles = 0;
};

extern std::list<std::string> candidate_state_responses;

int create_state_response(p2p::peer_outbound_message &msg, const p2p::state_request &sr);

void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id, const hasher::B2H expected_hash);

void start_state_sync(const hasher::B2H state_hash_to_request);

int run_state_sync_iterator();

void submit_request(const backlog_item &request);

int handle_fs_entry_response(const fbschema::p2pmsg::Fs_Entry_Response *fs_entry_resp);

int handle_file_hashmap_response(const fbschema::p2pmsg::File_HashMap_Response *file_resp);

int handle_file_block_response(const fbschema::p2pmsg::Block_Response *block_msg);

} // namespace cons

#endif