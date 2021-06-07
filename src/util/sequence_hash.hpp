#ifndef _HP_UTIL_SEQUENCE_HASH_
#define _HP_UTIL_SEQUENCE_HASH_

#include "../pchheader.hpp"
#include "util.hpp"
#include "h32.hpp"

namespace util
{
    struct sequence_hash
    {
        uint64_t seq_no = 0;
        util::h32 hash = util::h32_empty;

        bool operator!=(const sequence_hash &seq_hash) const;
        bool operator==(const sequence_hash &seq_hash) const;
        bool operator<(const sequence_hash &seq_hash) const;
        const std::string to_string();
        const bool empty() const;
    };

    // This is a helper method for sequence_hash structure which enables printing it straight away.
    std::ostream &operator<<(std::ostream &output, const sequence_hash &seq_hash);

} // namespace util

#endif