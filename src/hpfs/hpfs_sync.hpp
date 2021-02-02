#ifndef _HP_HPFS_HPFS_SYNC_
#define _HP_HPFS_HPFS_SYNC_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../msg/fbuf/p2pmsg_content_generated.h"
#include "../util/h32.hpp"
#include "../crypto.hpp"

namespace hpfs
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

    struct sync_target
    {
        std::string name; // Used for logging.
        util::h32 hash = util::h32_empty;
        std::string vpath;
        BACKLOG_ITEM_TYPE item_type = BACKLOG_ITEM_TYPE::DIR;

        bool operator==(const sync_target &target) const
        {
            return this->hash == target.hash;
        }
    };

    struct sync_context
    {
        // The current target hashes we are syncing towards.
        std::queue<sync_target> target_list;
        // Store the originally submitted sync target list. This list is used to avoid submitting same list multiple times
        // because target list is updated when the sync targets are acheived.
        std::queue<sync_target> original_target_list;
        sync_target current_target = {};

        // List of sender pubkeys and hpfs responses(flatbuffer messages) to be processed.
        std::list<std::pair<std::string, std::string>> candidate_hpfs_responses;

        // List of pending sync requests to be sent out.
        std::list<backlog_item> pending_requests;

        // List of submitted requests we are awaiting responses for, keyed by expected response path+hash.
        std::unordered_map<std::string, backlog_item> submitted_requests;

        std::thread hpfs_sync_thread;
        std::shared_mutex current_target_mutex;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;
    };

    class hpfs_sync
    {
    private:
        bool init_success = false;
        uint16_t REQUEST_RESUBMIT_TIMEOUT; // No. of milliseconds to wait before resubmitting a request.
        hpfs::hpfs_mount *fs_mount = NULL;
        std::string name;

        void hpfs_syncer_loop();

        int request_loop(const util::h32 current_target, util::h32 &updated_state);

        int start_syncing_next_target();

    protected:
        virtual void on_current_sync_state_acheived();
        virtual void swap_collected_responses(); // Must override in child classes.

    public:
        sync_context ctx;

        int init(std::string_view name, hpfs::hpfs_mount *fs_mount);

        void deinit();

        void set_target(const std::queue<sync_target> &target_list);

        bool validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entry_map);

        bool validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const util::h32 *hashes, const size_t hash_count);

        bool validate_file_block_hash(std::string_view hash, const uint32_t block_id, std::string_view buf);

        bool should_stop_request_loop(const util::h32 &current_target);

        void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                     const util::h32 expected_hash, std::string_view lcl, std::string &target_pubkey);

        void submit_request(const backlog_item &request, std::string_view lcl);

        int handle_fs_entry_response(std::string_view vpath, std::unordered_map<std::string, p2p::hpfs_fs_hash_entry> &fs_entry_map);

        int handle_file_hashmap_response(std::string_view vpath, const util::h32 *hashes, const size_t hash_count, const uint64_t file_length);

        int handle_file_block_response(std::string_view vpath, const uint32_t block_id, std::string_view buf);
    };

} // namespace hpfs

#endif