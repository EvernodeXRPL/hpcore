#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "ledger_schema_generated.h"
#include "common_helpers.hpp"
#include "ledger_helpers.hpp"

namespace msg::fbuf::ledger
{

    /**
     * Create ledger block from the given proposal struct.
     * @param p The proposal struct to be placed in ledger.
     */
    void create_ledger_block_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no, bool include_raw_input)
    {
        flatbuffers::Offset<ledger::LedgerBlock> ledger =
            ledger::CreateLedgerBlock(
                builder,
                seq_no,
                p.time,
                sv_to_flatbuff_bytes(builder, p.lcl),
                hash_to_flatbuff_bytes(builder, p.state),
                stringlist_to_flatbuf_bytearrayvector(builder, p.users),
                stringlist_to_flatbuf_bytearrayvector(builder, p.hash_inputs),
                stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs),
                include_raw_input ? create_raw_input_list_from_raw_input_map(builder, p.raw_inputs) : 0);

        builder.Finish(ledger); // Finished building message content to get serialised content.
    }

    /**
 * Returns Flatbuffer vector of raw inputs from given map.
 */
    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<msg::fbuf::ledger::RawInput>>>
    create_raw_input_list_from_raw_input_map(flatbuffers::FlatBufferBuilder &builder, const std::unordered_map<std::string, usr::raw_user_input> &map)
    {
        std::vector<flatbuffers::Offset<msg::fbuf::ledger::RawInput>> fbvec;
        fbvec.reserve(map.size());
        for (auto const &[key, value] : map)
        {
            fbvec.push_back(ledger::CreateRawInput(
                builder,
                sv_to_flatbuff_bytes(builder, key),
                CreateInput(
                    builder,
                    sv_to_flatbuff_bytes(builder, value.pubkey),
                    sv_to_flatbuff_bytes(builder, value.user_input.input_container),
                    sv_to_flatbuff_bytes(builder, value.user_input.sig),
                    (Input_Protocol)value.user_input.protocol)));
        }
        return builder.CreateVector(fbvec);
    }

    p2p::proposal create_proposal_from_ledger_block(const std::vector<uint8_t> &ledger_buf)
    {
        auto ledger = msg::fbuf::ledger::GetLedgerBlock(ledger_buf.data());
        p2p::proposal p;
        p.lcl = flatbuff_bytes_to_sv(ledger->lcl());
        p.state = flatbuff_bytes_to_hash(ledger->state());
        // We do not need to convert all the fields of the proposal due to them not being used for any ledger-specific logic.
        return p;
    }

    bool verify_ledger_block_buffer(const uint8_t *ledger_buf_ptr, const size_t buf_len)
    {
        flatbuffers::Verifier ledger_verifier(ledger_buf_ptr, buf_len);
        return VerifyLedgerBlockBuffer(ledger_verifier);
    }

} // namespace msg::fbuf::ledger
