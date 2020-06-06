#ifndef _HP_CONS_STATE_SYNC_
#define _HP_CONS_STATE_SYNC_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../hpfs/h32.hpp"

namespace state_sync
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
    hpfs::h32 expected_hash;

    // No. of cycles that this item has been waiting in pending state.
    // Used by pending_responses list to increase wait count.
    int16_t waiting_cycles = 0;
};

struct sync_context
{
    // The current target state we are syncing towards.
    hpfs::h32 target_state;

    // List of state responses flatbuffer messages to be processed.
    std::list<std::string> candidate_state_responses;

    // List of pending sync requests to be sent out.
    std::list<backlog_item> pending_requests;

    // List of submitted requests we are awaiting responses for, keyed by expected response hash.
    std::unordered_map<hpfs::h32, backlog_item, hpfs::h32_std_key_hasher> submitted_requests;

    bool is_state_syncing = false;

    bool should_stop_syncing = false;

    std::thread state_sync_thread;
};

extern sync_context ctx;

extern std::list<std::string> candidate_state_responses;

void sync_state(const hpfs::h32 target_state);

void stop_state_sync();

int state_syncer(const hpfs::h32 target_state);

int create_state_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::state_request &sr);

void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id, const hpfs::h32 expected_hash);

void submit_request(const backlog_item &request);

int handle_fs_entry_response(const fbschema::p2pmsg::Fs_Entry_Response *fs_entry_resp);

int handle_file_hashmap_response(const fbschema::p2pmsg::File_HashMap_Response *file_resp);

int handle_file_block_response(const fbschema::p2pmsg::Block_Response *block_msg);

} // namespace cons

#endif