#include "../pchheader.hpp"
#include "ledger_schema_generated.h"
#include "../p2p/p2p.hpp"
#include "common_helpers.hpp"
#include "ledger_helpers.hpp"

namespace fbschema::ledger
{

/**
 * Create ledger from the given proposal struct.
 * @param p The proposal struct to be placed in ledger.
 */
const std::string_view create_ledger_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no)
{
    flatbuffers::Offset<ledger::Ledger> ledger =
        ledger::CreateLedger(
            builder,
            seq_no,
            p.time,
            sv_to_flatbuff_bytes(builder, p.lcl),
            sv_to_flatbuff_bytes(builder, p.curr_hash_state.to_string_view()),
            stringlist_to_flatbuf_bytearrayvector(builder, p.users),
            stringlist_to_flatbuf_bytearrayvector(builder, p.hash_inputs),
            stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs));

    builder.Finish(ledger); // Finished building message content to get serialised content.

    return flatbuff_bytes_to_sv(builder.GetBufferPointer(), builder.GetSize());
}
} // namespace fbschema::ledger
