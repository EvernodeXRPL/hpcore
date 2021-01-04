#ifndef _HP_HPFS_HPFS_SYNC_
#define _HP_HPFS_HPFS_SYNC_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../util/h32.hpp"
#include "../crypto.hpp"

namespace hpfs_sync
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
        util::h32 expected_hash;

        // No. of millisconds that this item has been waiting in pending state.
        // Used by pending_responses list to increase waiting time and resubmit request.
        uint16_t waiting_time = 0;
    };

    struct sync_context
    {
        // The current target hashes we are syncing towards.
        util::h32 target_state_hash;
        util::h32 target_patch_hash;
        util::h32 current_parent_target_hash;

        hpfs::HPFS_PARENT_COMPONENTS current_syncing_parent;

        // List of sender pubkeys and hpfs responses(flatbuffer messages) to be processed.
        std::list<std::pair<std::string, std::string>> candidate_hpfs_responses;

        // List of pending sync requests to be sent out.
        std::list<backlog_item> pending_requests;

        // List of submitted requests we are awaiting responses for, keyed by expected response path+hash.
        std::unordered_map<std::string, backlog_item> submitted_requests;

        std::thread hpfs_sync_thread;
        std::shared_mutex target_state_mutex;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;
        std::string hpfs_mount_dir;
    };

    extern sync_context ctx;

    int init();

    void deinit();

    void set_target(const util::h32 target_state_hash, const util::h32 target_patch_hash);

    void hpfs_syncer_loop();

    int request_loop(const util::h32 current_target, util::h32 &updated_state);

    bool validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entry_map);

    bool validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const util::h32 *hashes, const size_t hash_count);

    bool validate_file_block_hash(std::string_view hash, const uint32_t block_id, std::string_view buf);

    bool should_stop_request_loop(const util::h32 current_target);

    void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                 const util::h32 expected_hash, std::string_view lcl, std::string &target_pubkey);

    void submit_request(const backlog_item &request, std::string_view lcl);

    int handle_fs_entry_response(std::string_view vpath, std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entry_map);

    int handle_file_hashmap_response(std::string_view vpath, const util::h32 *hashes, const size_t hash_count, const uint64_t file_length);

    int handle_file_block_response(std::string_view vpath, const uint32_t block_id, std::string_view buf);

} // namespace hpfs_sync

#endif