#ifndef _HP_LEDGER_LEDGER_QUERY_
#define _HP_LEDGER_LEDGER_QUERY_

#include "../pchheader.hpp"
#include "ledger_common.hpp"

namespace ledger::query
{
    /**
     * Represents a ledger query request to filter by seq no.
     */
    struct seq_no_query
    {
        uint64_t seq_no = 0;
        bool raw_inputs = false;
        bool raw_outputs = false;
    };

    typedef std::map<std::string, std::vector<std::string>> blob_map;

    struct query_result_record
    {
        ledger::ledger_record ledger;
        std::optional<blob_map> raw_inputs;
        std::optional<blob_map> raw_outputs;
    };

    struct user_buffer_collection
    {
        std::string pubkey;               // Binary user pubkey.
        std::vector<std::string> buffers; // List of binary data buffers.
    };

    typedef std::variant<seq_no_query> query_request;
    typedef std::variant<const char *, std::vector<query_result_record>> query_result;

    const query_result execute(std::string_view user_pubkey, const query_request &q);
    int fill_blob_data(std::vector<query_result_record> &records, const bool raw_inputs, const bool raw_outputs, const std::string &fs_sess_name);
    int get_ledger_by_seq_no(ledger_record &ledger, const seq_no_query &q, const std::string &fs_sess_name);
}

#endif