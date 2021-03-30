#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "ledger_blob_schema_generated.h"
#include "common_helpers.hpp"
#include "ledger_helpers.hpp"

namespace msg::fbuf::ledgermsg
{
    /**
     * Create ledger blob msg from ledger blob struct.
     * @param ledger_blob Ledger blob to be placed in file.
     */
    void create_ledger_blob_msg_from_ledger_blob(flatbuffers::FlatBufferBuilder &builder, const ledger::ledger_blob &ledger_blob)
    {
        std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawInputCollection>> raw_inputs;
        raw_inputs.reserve(ledger_blob.inputs.size());
        std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawOutputCollection>> raw_outputs;
        raw_outputs.reserve(ledger_blob.outputs.size());

        for (const auto &[key, value] : ledger_blob.inputs)
        {
            std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawInput>> inputs;
            inputs.reserve(value.size());

            for (const auto &input : value)
                inputs.push_back(ledgermsg::CreateRawInput(builder, sv_to_flatbuf_bytes(builder, input)));

            raw_inputs.push_back(ledgermsg::CreateRawInputCollection(
                builder,
                sv_to_flatbuf_bytes(builder, key),
                builder.CreateVector(inputs)));
        }

        for (const auto &[key, value] : ledger_blob.outputs)
        {
            std::vector<flatbuffers::Offset<msg::fbuf::ledgermsg::RawOutput>> outputs;
            outputs.reserve(value.size());

            for (const auto &output : value)
                outputs.push_back(ledgermsg::CreateRawOutput(builder, sv_to_flatbuf_bytes(builder, output)));

            raw_outputs.push_back(ledgermsg::CreateRawOutputCollection(
                builder,
                sv_to_flatbuf_bytes(builder, key),
                builder.CreateVector(outputs)));
        }

        flatbuffers::Offset<ledgermsg::LedgerBlob> blob =
            ledgermsg::CreateLedgerBlob(
                builder,
                hash_to_flatbuf_bytes(builder, ledger_blob.ledger_hash),
                builder.CreateVector(raw_inputs),
                builder.CreateVector(raw_outputs));

        builder.Finish(blob); // Finished building message content to get serialised content.
    }

    const int create_ledger_blob_from_msg(ledger::ledger_blob &blob_data, const std::string &msg, const bool read_inputs, const bool read_outputs)
    {
        // Verify ledger blob using flatbuffer verifier
        flatbuffers::Verifier verifier((uint8_t *)msg.data(), msg.size(), 16, 100);
        if (!VerifyLedgerBlobBuffer(verifier))
        {
            LOG_ERROR << "Ledger blob flatbuffer verification failed.";
            return -1;
        }

        const auto ledger_msg = ledgermsg::GetLedgerBlob(msg.data());
        blob_data.ledger_hash = flatbuf_bytes_to_hash(ledger_msg->ledger_hash());

        if (read_inputs)
        {
            std::vector<std::string> inputs;
            for (const auto collection : *ledger_msg->raw_inputs())
            {
                for (const auto input_msg : *collection->inputs())
                {
                    inputs.push_back(std::string(flatbuf_bytes_to_sv(input_msg->input())));
                }

                blob_data.inputs.emplace(std::string(flatbuf_bytes_to_sv(collection->pubkey())), std::move(inputs));
            }
        }

        if (read_outputs)
        {
            std::vector<std::string> outputs;
            for (const auto collection : *ledger_msg->raw_outputs())
            {
                for (const auto output_msg : *collection->outputs())
                {
                    outputs.push_back(std::string(flatbuf_bytes_to_sv(output_msg->output())));
                }

                blob_data.outputs.emplace(std::string(flatbuf_bytes_to_sv(collection->pubkey())), std::move(outputs));
            }
        }

        return 0;
    }

} // namespace msg::fbuf::ledgermsg
