#ifndef _HP_HPFS_HPFS_SYNC_
#define _HP_HPFS_HPFS_SYNC_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../util/h32.hpp"
#include "./hpfs_mount.hpp"

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
        uint32_t waiting_time = 0;
    };

    struct sync_target
    {
        std::string name; // Used for logging.
        util::h32 hash = util::h32_empty;
        std::string vpath;
        BACKLOG_ITEM_TYPE item_type = BACKLOG_ITEM_TYPE::DIR;

        bool operator==(const sync_target &target) const
        {
            return this->vpath == target.vpath && this->hash == target.hash;
        }
    };

    class hpfs_sync
    {
    private:
        bool init_success = false;
        std::string name; // Name used for logging.

        sync_target current_target = {};
        std::list<sync_target> target_list; // The current target hashes we are syncing towards.

        // Store the originally submitted sync target list. This list is used to avoid submitting same list multiple times
        // because target list is updated when the sync targets are acheived.
        std::list<sync_target> original_target_list;

        std::list<backlog_item> pending_requests; // List of pending sync requests to be sent out.

        // List of submitted requests we are awaiting responses for, keyed by expected response path+hash.
        std::unordered_map<std::string, backlog_item> submitted_requests;

        std::thread hpfs_sync_thread;
        std::shared_mutex current_target_mutex;
        std::atomic<bool> is_shutting_down = false;

        void hpfs_syncer_loop();

        int request_loop(const util::h32 current_target_hash, util::h32 &updated_state);

        int start_syncing_next_target();

        bool validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const mode_t dir_mode,
                                    const std::vector<p2p::hpfs_fs_hash_entry> &peer_fs_entries);

        bool validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const mode_t file_mode,
                                        const util::h32 *hashes, const size_t hash_count);

        bool validate_file_block_hash(std::string_view hash, const uint32_t block_id, std::string_view buf);

        bool should_stop_request_loop(const util::h32 &current_target_hash);

        void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                     const util::h32 expected_hash, std::string &target_pubkey);

        void submit_request(const backlog_item &request, const bool watch_only = false);

        int handle_fs_entry_response(std::string_view vpath, const mode_t dir_mode, const std::vector<p2p::hpfs_fs_hash_entry> &peer_fs_entries);

        int handle_file_hashmap_response(std::string_view vpath, const mode_t file_mode, const util::h32 *hashes, const size_t hash_count,
                                         const std::set<uint32_t> &responded_block_ids, const uint64_t file_length);

        int handle_file_block_response(std::string_view vpath, const uint32_t block_id, std::string_view buf);

        int apply_metadata_mode(std::string_view physical_path, const mode_t mode, const bool is_dir);

    protected:
        // List of sender pubkeys and hpfs responses(flatbuffer messages) to be processed.
        std::list<std::pair<std::string, std::string>> candidate_hpfs_responses;

        hpfs::hpfs_mount *fs_mount = NULL;

        virtual void on_current_sync_state_acheived(const sync_target &synced_target);

        virtual void on_sync_abandoned();

        virtual void on_sync_complete(const sync_target &last_sync_target);

        // Move the collected responses from hpfs responses to a local response list.
        virtual void swap_collected_responses() = 0; // Must override in child classes.

        int reacquire_rw_session();

    public:
        std::atomic<bool> is_syncing = false;

        int init(std::string_view worker_name, hpfs::hpfs_mount *fs_mount_ptr);

        void deinit();

        void set_target(const std::list<sync_target> &sync_target_list);

        void set_target_push_front(const sync_target &target);

        void set_target_push_back(const sync_target &target);
    };

} // namespace hpfs

#endif