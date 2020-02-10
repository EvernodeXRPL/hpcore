#ifndef _HP_CONS_LEDGER_
#define _HP_CONS_LEDGER_

#include "../pchheader.hpp"
#include "../p2p/p2p.hpp"

namespace cons
{

//max ledger count
constexpr uint64_t MAX_LEDGER_SEQUENCE = 200;
constexpr const char* GENESIS_LEDGER = "0-genesis";
struct ledger_cache_entry
{
    std::string lcl;
    std::string state;
};

struct ledger_history
{
    std::string lcl;
    uint64_t led_seq_no;
    std::map<uint64_t, ledger_cache_entry> cache;
};

const std::tuple<const uint64_t, std::string> save_ledger(const p2p::proposal &proposal);

void remove_old_ledgers(const uint64_t led_seq_no);

void write_ledger(const std::string &file_name, const char *ledger_raw, size_t ledger_size);

void remove_ledger(const std::string &file_name);

const ledger_history load_ledger();

void send_ledger_history_request(const std::string &minimum_lcl, const std::string &required_lcl);

bool check_required_lcl_availability(const p2p::history_request &hr);

const p2p::history_response retrieve_ledger_history(const p2p::history_request &hr);

p2p::peer_outbound_message send_ledger_history(const p2p::history_request &hr);

void handle_ledger_history_response(const p2p::history_response &hr);

} // namespace cons

#endif