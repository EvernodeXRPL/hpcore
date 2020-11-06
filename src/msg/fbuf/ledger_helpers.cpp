#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "ledger_schema_generated.h"
#include "common_helpers.hpp"
#include "ledger_helpers.hpp"

namespace msg::fbuf::ledger
{

    /**
 * Create ledger from the given proposal struct.
 * @param p The proposal struct to be placed in ledger.
 */
    void create_ledger_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no)
    {
        flatbuffers::Offset<ledger::Ledger> ledger =
            ledger::CreateLedger(
                builder,
                seq_no,
                p.time,
                sv_to_flatbuff_bytes(builder, p.lcl),
                hash_to_flatbuff_bytes(builder, p.state),
                stringlist_to_flatbuf_bytearrayvector(builder, p.users),
                stringlist_to_flatbuf_bytearrayvector(builder, p.hash_inputs),
                stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs));

        builder.Finish(ledger); // Finished building message content to get serialised content.
    }

    p2p::proposal create_proposal_from_ledger(const std::vector<uint8_t> &ledger_buf)
    {
        auto ledger = msg::fbuf::ledger::GetLedger(ledger_buf.data());
        p2p::proposal p;
        p.lcl = flatbuff_bytes_to_sv(ledger->lcl());
        p.state = flatbuff_bytes_to_hash(ledger->state());
        // We do not need to convert all the fields of the proposal due to them not being used for any ledger-specific logic.
        return p;
    }

    bool verify_ledger_buffer(const uint8_t *ledger_buf_ptr, const size_t buf_len)
    {
        flatbuffers::Verifier ledger_verifier(ledger_buf_ptr, buf_len);
        return VerifyLedgerBuffer(ledger_verifier);
    }

} // namespace msg::fbuf::ledger
