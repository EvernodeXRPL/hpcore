#include <flatbuffers/flatbuffers.h>
#include "ledger_schema_generated.h"
#include "../p2p/p2p.hpp"
#include "common_helpers.hpp"
#include "ledger_schema_helpers.hpp"

namespace fbschema
{

/**
 * Ctreat ledger from the given proposal struct.
 * @param p The proposal struct to be placed in ledger.
 */
std::string_view create_ledger_from_proposal(const p2p::proposal &p)
{
    flatbuffers::FlatBufferBuilder builder(1024);

    flatbuffers::Offset<cons::Ledger> ledger =
        cons::CreateLedger(
            builder,
            p.time,
            sv_to_flatbuff_bytes(builder, p.lcl),
            stringlist_to_flatbuf_bytearrayvector(builder, p.users), 0, 0
            //p2p::hashbuffermap_to_flatbuf_rawinputs(builder, p.raw_inputs),
            //stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs)
            );

    builder.Finish(ledger); // Finished building message content to get serialised content.

    return flatbuff_bytes_to_sv(builder.GetBufferPointer(), builder.GetSize());
}
} // namespace fbschema
