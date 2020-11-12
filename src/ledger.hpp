#ifndef _HP_LEDGER_
#define _HP_LEDGER_

#include "pchheader.hpp"
#include "p2p/p2p.hpp"

namespace ledger
{
    constexpr const char *GENESIS_LEDGER = "0-genesis";

    struct sync_context
    {
        // The current target lcl that we are syncing towards.
        std::string target_lcl;
        std::mutex target_lcl_mutex;

        // Lists holding history requests and responses collected from incoming p2p messages.
        std::list<std::pair<std::string, p2p::history_request>> collected_history_requests;
        std::list<p2p::history_response> collected_history_responses;
        std::mutex list_mutex;

        std::thread lcl_sync_thread;
        std::atomic<bool> is_syncing = false;
        std::atomic<bool> is_shutting_down = false;
    };

    struct ledger_context
    {
    private:
        std::string lcl;
        uint64_t seq_no = 0;
        std::shared_mutex lcl_mutex;

    public:
        // Map of closed ledgers (lcl string) with sequence number as map key.
        // Contains closed ledgers from oldest to latest - MAX_LEDGER_SEQUENCE.
        // This is loaded when node started and updated throughout consensus.
        // Deletes ledgers that falls behind MAX_LEDGER_SEQUENCE range.
        std::map<uint64_t, const std::string> cache;

        std::mutex ledger_mutex;

        const std::string get_lcl()
        {
            std::shared_lock lock(lcl_mutex);
            return lcl;
        }

        uint64_t get_seq_no()
        {
            std::shared_lock lock(lcl_mutex);
            return seq_no;
        }

        void set_lcl(const uint64_t new_seq_no, std::string_view new_lcl)
        {
            std::unique_lock lock(lcl_mutex);
            lcl = new_lcl;
            seq_no = new_seq_no;
        }
    };

    extern sync_context sync_ctx;
    extern ledger_context ctx;

    int init();

    void deinit();

    void lcl_syncer_loop();
    
    void set_sync_target(std::string_view target_lcl);

    const std::pair<uint64_t, std::string> get_ledger_cache_top();

    int save_ledger(const p2p::proposal &proposal);

    void remove_old_ledgers(const uint64_t led_seq_no);

    void clear_ledger();

    int read_ledger(std::string_view file_path, std::vector<uint8_t> &buffer);

    int write_ledger(const std::string &file_name, const uint8_t *ledger_raw, const size_t ledger_size);

    void remove_ledger(const std::string &file_name);

    void send_ledger_history_request(std::string_view minimum_lcl, std::string_view required_lcl);

    bool check_required_lcl_availability(const std::string &required_lcl);

    int retrieve_ledger_history(const p2p::history_request &hr, p2p::history_response &history_response);

    int handle_ledger_history_response(const p2p::history_response &hr, std::string &new_lcl);

    bool check_block_integrity(std::string_view lcl, const std::vector<uint8_t> &raw_ledger);

    int sort_lcl_filenames_and_validate(std::list<std::string> &list);

} // namespace ledger

#endif