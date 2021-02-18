#ifndef _HP_MSG_FBUF_LEDGER_HELPERS_
#define _HP_MSG_FBUF_LEDGER_HELPERS_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "../../ledger/ledger.hpp"
#include "ledger_schema_generated.h"

namespace msg::fbuf::ledgermsg
{

    void create_ledger_blob_msg_from_ledger_blob(flatbuffers::FlatBufferBuilder &builder, const ledger::ledger_blob &ledger_blob);

} // namespace msg::fbuf::ledgermsg

#endif