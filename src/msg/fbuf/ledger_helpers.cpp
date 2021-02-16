#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "ledger_schema_generated.h"
#include "ledger_blob_schema_generated.h"
#include "common_helpers.hpp"
#include "ledger_helpers.hpp"

namespace msg::fbuf::ledgermsg
{
    /**
     * Create ledger block from the given proposal struct.
     * @param p The proposal struct to be placed in ledger.
     */
    void create_ledger_block_from_proposal(flatbuffers::FlatBufferBuilder &builder, const p2p::proposal &p, const uint64_t seq_no)
    {
        flatbuffers::Offset<ledgermsg::LedgerBlock> ledger =
            ledgermsg::CreateLedgerBlock(
                builder,
                sv_to_flatbuff_str(builder, conf::cfg.hp_version),
                seq_no,
                p.time,
                sv_to_flatbuff_bytes(builder, p.lcl),
                hash_to_flatbuff_bytes(builder, p.state_hash),
                hash_to_flatbuff_bytes(builder, p.patch_hash),
                stringlist_to_flatbuf_bytearrayvector(builder, p.users),
                stringlist_to_flatbuf_bytearrayvector(builder, p.input_hashes),
                sv_to_flatbuff_bytes(builder, p.output_hash));

        builder.Finish(ledger); // Finished building message content to get serialised content.
    }

    p2p::proposal create_proposal_from_ledger_block(const std::vector<uint8_t> &ledger_buf)
    {
        auto ledger = msg::fbuf::ledgermsg::GetLedgerBlock(ledger_buf.data());
        p2p::proposal p;
        p.lcl = flatbuff_bytes_to_sv(ledger->lcl());
        p.state_hash = flatbuff_bytes_to_hash(ledger->state_hash());
        p.patch_hash = flatbuff_bytes_to_hash(ledger->patch_hash());
        // We do not need to convert all the fields of the proposal due to them not being used for any ledger-specific logic.
        return p;
    }

    bool verify_ledger_block_buffer(const uint8_t *ledger_buf_ptr, const size_t buf_len)
    {
        flatbuffers::Verifier ledger_verifier(ledger_buf_ptr, buf_len);
        return VerifyLedgerBlockBuffer(ledger_verifier);
    }

    /**
     * Create ledger blob msg from ledger blob struct.
     * @param ledger_blob Ledger blob to be placed in file.
     */
    void create_ledger_blob_msg_from_ledger_blob(flatbuffers::FlatBufferBuilder &builder, const ledger::ledger_blob &ledger_blob)
    {
        std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawInputCollection>> raw_inputs;
        raw_inputs.resize(ledger_blob.inputs.size());
        std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawOutputCollection>> raw_outputs;
        raw_outputs.resize(ledger_blob.outputs.size());

        for (const auto &[key, value] : ledger_blob.inputs)
        {
            std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawInput>> inputs;
            for (const auto &input : value)
            {
                inputs.push_back(ledgermsg::CreateRawInput(builder, sv_to_flatbuff_bytes(builder, input)));
            }

            raw_inputs.push_back(ledgermsg::CreateRawInputCollection(
                builder,
                sv_to_flatbuff_bytes(builder, key),
                builder.CreateVector(inputs)));
        }

        for (const auto &[key, value] : ledger_blob.outputs)
        {
            std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawOutput>> outputs;
            for (const auto &output : value)
            {
                outputs.push_back(ledgermsg::CreateRawOutput(builder, sv_to_flatbuff_bytes(builder, output)));
            }

            raw_outputs.push_back(ledgermsg::CreateRawOutputCollection(
                builder,
                sv_to_flatbuff_bytes(builder, key),
                builder.CreateVector(outputs)));
        }

        flatbuffers::Offset<ledgermsg::LedgerBlob> blob =
            ledgermsg::CreateLedgerBlob(
                builder,
                sv_to_flatbuff_bytes(builder, ledger_blob.ledger_hash),
                builder.CreateVector(raw_inputs),
                builder.CreateVector(raw_outputs));

        builder.Finish(blob); // Finished building message content to get serialised content.
    }
} // namespace msg::fbuf::ledgermsg
