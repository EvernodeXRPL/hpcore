#ifndef _HP_UNL_
#define _HP_UNL_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"

/**
 * Manages the UNL public keys of this node.
 */
namespace unl
{
    struct sync_context
    {
        // The current target unl that we are syncing towards.
        std::string target_unl;
        std::mutex target_unl_mutex;

        // Lists holding unl requests and responses collected from incoming p2p messages.
        std::list<std::pair<std::string, p2p::unl_sync_request>> collected_unl_sync_requests;
        std::list<p2p::unl_sync_response> collected_unl_sync_responses;
        std::mutex list_mutex;

        uint64_t target_requested_on = 0;
        uint64_t request_submissions = 0;

        std::thread unl_sync_thread;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;

        void clear_target()
        {
            target_unl.clear();
            target_requested_on = 0;
            request_submissions = 0;
            is_syncing = false;
        }
    };
    extern sync_context sync_ctx;
    constexpr uint16_t UNL_REQ_LIST_CAP = 64; // Maximum unl request count.
    constexpr uint16_t UNL_RES_LIST_CAP = 64; // Maximum unl response count.

    size_t count();
    std::set<std::string> get();
    std::string get_json();
    bool exists(const std::string &bin_pubkey);
    int init(const std::set<std::string> &init_list);
    void deinit();
    void apply_changeset(const std::set<std::string> &additions, const std::set<std::string> &removals);
    void update_json_list();
    std::string get_hash();
    std::string calculate_hash(const std::set<std::string> &new_list);
    void set_sync_target(std::string_view target_unl_hash);
    void send_unl_sync_request();
    void unl_syncer_loop();
    std::string hash_bin2hex(std::string_view hash);
    int verify_and_replace(const std::set<std::string> &new_list);
    int check_unl_sync_requests();
    int check_unl_sync_responses();

} // namespace unl

#endif
