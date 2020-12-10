#ifndef _HP_STATE_STATE_SYNC_
#define _HP_STATE_STATE_SYNC_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../hpfs/h32.hpp"
#include "../crypto.hpp"

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
        BACKLOG_ITEM_TYPE type = BACKLOG_ITEM_TYPE::DIR;
        std::string path;
        int32_t block_id = -1; // Only relevant if type=BLOCK
        hpfs::h32 expected_hash;

        // No. of millisconds that this item has been waiting in pending state.
        // Used by pending_responses list to increase waiting time and resubmit request.
        uint16_t waiting_time = 0;
    };

    struct sync_context
    {
        // The current target state we are syncing towards.
        hpfs::h32 target_state;

        // List of sender pubkeys and state responses(flatbuffer messages) to be processed.
        std::list<std::pair<std::string, std::string>> candidate_state_responses;

        // List of pending sync requests to be sent out.
        std::list<backlog_item> pending_requests;

        // List of submitted requests we are awaiting responses for, keyed by expected response path+hash.
        std::unordered_map<std::string, backlog_item> submitted_requests;

        std::thread state_sync_thread;
        std::shared_mutex target_state_mutex;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;
        std::string hpfs_mount_dir;
    };

    extern sync_context ctx;

    extern std::list<std::string> candidate_state_responses;

    int init();

    void deinit();

    void set_target(const hpfs::h32 target_state);

    void state_syncer_loop();

    int request_loop(const hpfs::h32 current_target, hpfs::h32 &updated_state);

    bool validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const std::unordered_map<std::string, p2p::state_fs_hash_entry> peer_fs_entry_map);

    bool validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const hpfs::h32 *peer_hashes, const size_t peer_hash_count);

    bool validate_file_block_hash(std::string_view vpath, std::string_view hash, const uint32_t block_id, std::string_view buf);

    bool should_stop_request_loop(const hpfs::h32 current_target);

    void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                 const hpfs::h32 expected_hash, std::string_view lcl, std::string &target_pubkey);

    void submit_request(const backlog_item &request, std::string_view lcl);

    int handle_fs_entry_response(std::string_view parent_vpath, std::unordered_map<std::string, p2p::state_fs_hash_entry> peer_fs_entry_map);

    int handle_file_hashmap_response(std::string_view file_vpath, const hpfs::h32 *peer_hashes, const size_t peer_hash_count, const uint64_t file_length);

    int handle_file_block_response(std::string_view file_vpath, const uint32_t block_id, std::string_view buf);

} // namespace state_sync

#endif