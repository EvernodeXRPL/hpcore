#ifndef _HP_HPFS_HPFS_SYNC_
#define _HP_HPFS_HPFS_SYNC_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"
#include "../util/h32.hpp"
#include "./hpfs_mount.hpp"

namespace hpfs
{

    enum SYNC_ITEM_TYPE
    {
        DIR = 0,
        FILE = 1,
        BLOCK = 2
    };

    // Represents a queued up state sync operation which needs to be performed.
    struct sync_item
    {
        SYNC_ITEM_TYPE type = SYNC_ITEM_TYPE::DIR;
        std::string vpath;
        int32_t block_id = -1; // Only relevant if type=BLOCK
        util::h32 expected_hash;
        bool high_priority = false;

        // No. of millisconds that this item has been waiting in pending state.
        // Used by pending_responses list to increase waiting time and resubmit request.
        uint32_t waiting_time = 0;

        uint32_t priority() const
        {
            // Lesser value means higher priority.
            /**
             * Priority order:
             * High prio file block
             * High prio file hashmap
             * High prio dir children
             * Low prio file block
             * Low prio file hashmap
             * Low prio dir children
             */

            return ((high_priority ? 1 : 2) * 10) + (type == SYNC_ITEM_TYPE::BLOCK ? 1 : (type == SYNC_ITEM_TYPE::FILE ? 2 : 3));
        }

        bool operator==(const sync_item &other) const
        {
            return type == other.type && vpath == other.vpath && block_id == other.block_id && expected_hash == other.expected_hash;
        }

        bool operator<(const sync_item &other) const
        {
            const uint32_t prio = priority();
            const uint32_t other_prio = other.priority();
            if (prio == other_prio)
            {
                if (vpath == other.vpath)
                    return block_id < other.block_id;
                else
                    return vpath < other.vpath;
            }
            else
            {
                return prio < other_prio;
            }
        }
    };

    class hpfs_sync
    {
    private:
        bool init_success = false;
        std::string name; // Name used for logging.

        std::shared_mutex incoming_targets_mutex;
        std::set<sync_item> incoming_targets; // The targets that we need to sync towards but have not looked at yet.

        std::vector<sync_item> ongoing_targets; // The targets that we have taken into processing.
        std::set<sync_item> pending_requests;   // List of pending sync requests to be sent out.
        // List of submitted requests we are awaiting responses for, keyed by expected response path+hash.
        std::unordered_map<std::string, sync_item> submitted_requests;

        // No. of repetitive resubmissions so far. (This is reset whenever we receive a hpfs response)
        uint16_t resubmissions_count = 0;

        std::thread hpfs_sync_thread;
        std::atomic<bool> is_shutting_down = false;

        void hpfs_syncer_loop();

        int check_incoming_targets();

        void perform_request_submissions();

        void update_sync_status();

        bool process_candidate_responses();

        bool validate_fs_entry_hash(std::string_view vpath, std::string_view hash, const mode_t dir_mode,
                                    const std::vector<p2p::hpfs_fs_hash_entry> &peer_fs_entries);

        bool validate_file_hashmap_hash(std::string_view vpath, std::string_view hash, const mode_t file_mode,
                                        const util::h32 *hashes, const size_t hash_count);

        bool validate_file_block_hash(std::string_view hash, const uint32_t block_id, std::string_view buf);

        void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id,
                                     const util::h32 expected_hash, std::string &target_pubkey);

        void submit_request(const sync_item &request, const bool watch_only = false, const bool is_resubmit = false);

        int handle_fs_entry_response(std::string_view vpath, const mode_t dir_mode, const std::vector<p2p::hpfs_fs_hash_entry> &peer_fs_entries);

        int handle_file_hashmap_response(std::string_view vpath, const mode_t file_mode, const util::h32 *hashes, const size_t hash_count,
                                         const std::set<uint32_t> &responded_block_ids, const uint64_t file_length);

        int handle_file_block_response(std::string_view vpath, const uint32_t block_id, std::string_view buf);

        int apply_metadata_mode(std::string_view physical_path, const mode_t mode, const bool is_dir);

    protected:
        // List of sender pubkeys and hpfs responses(flatbuffer messages) to be processed.
        std::list<std::pair<std::string, std::string>> candidate_hpfs_responses;

        hpfs::hpfs_mount *fs_mount = NULL;

        virtual void on_sync_target_acheived(const std::string &vpath, const util::h32 &hash);

        virtual void on_sync_abandoned();

        // Move the collected responses from hpfs responses to a local response list.
        virtual void swap_collected_responses() = 0; // Must override in child classes.

        int reacquire_rw_session();

    public:
        std::atomic<bool> is_syncing = false;

        int init(std::string_view worker_name, hpfs::hpfs_mount *fs_mount_ptr);

        void deinit();

        void set_target(const bool is_dir, const std::string &vpath,
                        const util::h32 &hash, const bool high_priority = false);
    };

} // namespace hpfs

#endif