#ifndef _HP_SC_HPFS_LOG_SYNC
#define _HP_SC_HPFS_LOG_SYNC

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

/**
 * This namespace is responsible for contract state syncing in full history modes. Full history nodes cannot use normal hpfs sync since replay ability should be preserved.
 * Hence log file records are requested from another full history node.
*/
namespace sc::hpfs_log_sync
{
    struct sync_context
    {
        // The current target log record that we are syncing towards.
        p2p::sequence_hash target_log_record;
        std::mutex target_log_record_mutex;
        p2p::sequence_hash min_log_record;
        std::mutex min_log_record_mutex;
        uint64_t target_requested_on = 0;
        uint16_t request_submissions = 0;

        std::thread log_record_sync_thread;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;

        void clear_target()
        {
            target_log_record = {};
            min_log_record = {};
            target_requested_on = 0;
            request_submissions = 0;
            is_syncing = false;
        }
    };
    extern sync_context sync_ctx;

    int init();

    void deinit();

    void set_sync_target(const p2p::sequence_hash target);

    void hpfs_log_syncer_loop();

    void send_hpfs_log_sync_request();

    int check_hpfs_log_sync_responses();

    int check_hpfs_log_sync_requests();

    bool check_required_log_record_availability(const p2p::sequence_hash &min_log_record);

    int handle_hpfs_log_sync_response(const p2p::hpfs_log_response &hr, std::string &new_lcl);

    int get_verified_min_record();

    int set_joining_point_for_fork(const uint64_t starting_point);
}
#endif