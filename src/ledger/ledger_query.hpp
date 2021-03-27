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

    struct query_result_record
    {
        ledger::ledger_record ledger;
        // TODO:
        // RawInputs field.
        // RawOutputs field.
    };

    typedef std::variant<seq_no_query> query_request;
    typedef std::variant<const char *, std::vector<query_result_record>> query_result;

    const query_result execute(std::string_view user_pubkey, const query_request &q);
    int get_ledger_by_seq_no(ledger_record &ledger, const seq_no_query &q, const std::string &fs_sess_name);
}

#endif