#ifndef _HP_LEDGER_LEDGER_QUERY_
#define _HP_LEDGER_LEDGER_QUERY_

#include "../pchheader.hpp"

namespace ledger::query
{
    enum INCLUDES
    {
        SUMMARY = 0,
        RAW_INPUTS = 1,
        RAW_OUTPUTS = 2
    };

    /**
     * Represents a ledger query request to filter by seq no.
     */
    struct seq_no_query
    {
        std::string id;
        uint64_t seq_no = 0;
        std::bitset<3> include;
    };

    typedef std::variant<seq_no_query> query_request;

    struct query_result
    {
        
    };
}

#endif