#include "sequence_hash.hpp"

namespace util
{
    bool sequence_hash::operator!=(const sequence_hash &seq_hash) const
    {
        return seq_no != seq_hash.seq_no || hash != seq_hash.hash;
    }

    bool sequence_hash::operator==(const sequence_hash &seq_hash) const
    {
        return seq_no == seq_hash.seq_no && hash == seq_hash.hash;
    }

    bool sequence_hash::operator<(const sequence_hash &seq_hash) const
    {
        return (seq_no == seq_hash.seq_no) ? hash < seq_hash.hash : seq_no < seq_hash.seq_no;
    }

    const std::string sequence_hash::to_string()
    {
        return std::to_string(seq_no) + "-" + util::to_hex(hash.to_string_view());
    }

    const bool sequence_hash::empty() const
    {
        return seq_no == 0 && hash == util::h32_empty;
    }

    std::ostream &operator<<(std::ostream &output, const sequence_hash &seq_hash)
    {
        output << seq_hash.seq_no << "-" << seq_hash.hash;
        return output;
    }

} // namespace util