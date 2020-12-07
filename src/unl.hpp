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

        std::thread unl_sync_thread;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;
    };
    extern sync_context sync_ctx;
    constexpr uint16_t UNL_REQ_LIST_CAP = 64; // Maximum unl request count.
    constexpr uint16_t UNL_RES_LIST_CAP = 64; // Maximum unl response count.

    size_t count();
    std::set<std::string> get();
    std::string get_json();
    bool exists(const std::string &bin_pubkey);
    void init(const std::set<std::string> &init_list);
    void deinit();
    void update(const std::vector<std::string> &additions, const std::vector<std::string> &removals);
    void update_json_list();
    std::string get_hash();
    std::string calculate_hash(const std::set<std::string> &new_list);
    void set_sync_target(std::string_view target_unl_hash);
    void send_unl_sync_request(std::string_view required_unl);
    void unl_syncer_loop();
    std::string hash_bin2hex(std::string_view hash);
    int verify_and_replace(const std::set<std::string> &new_list);

} // namespace unl

#endif
