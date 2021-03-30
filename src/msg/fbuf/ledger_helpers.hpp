#ifndef _HP_MSG_FBUF_LEDGER_HELPERS_
#define _HP_MSG_FBUF_LEDGER_HELPERS_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "../../ledger/ledger.hpp"

namespace msg::fbuf::ledgermsg
{
    void create_ledger_blob_msg_from_ledger_blob(flatbuffers::FlatBufferBuilder &builder, const ledger::ledger_blob &ledger_blob);

    const int create_ledger_blob_from_msg(ledger::ledger_blob &blob_data, const std::string &msg, const bool read_inputs, const bool read_outputs);

} // namespace msg::fbuf::ledgermsg

#endif