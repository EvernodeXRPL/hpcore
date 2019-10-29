
#include <flatbuffers/flatbuffers.h>
#include <iostream>
#include <fstream>
#include "conf.hpp"
#include "crpto.hpp"
#include "../p2p/p2p.hpp"
#include "../p2p/peer_message_handler.hpp"
#include "ledger_generated.h"
#include "ledger_handler.hpp"

namespace cons
{

void save_ledger(const p2p::proposal &proposal)
{
}

void load_ledger()
{
}

/**
 * Ctreat proposal peer message from the given proposal struct.
 * @param container_builder Flatbuffer builder for the container message.
 * @param p The proposal struct to be placed in the container message.
 */
void create_msg_from_proposal(flatbuffers::FlatBufferBuilder &container_builder, const p2p::proposal &p)
{
    // todo:get a average propsal message size and allocate content builder based on that.
    flatbuffers::FlatBufferBuilder builder(1024);

    // Create dummy propsal message
    flatbuffers::Offset<Ledger> ledger =
        CreateLedger(
            builder,
            p.time,
            p2p::sv_to_flatbuff_bytes(builder, p.lcl), 0, 0, 0
            //p2p::stringlist_to_flatbuf_bytearrayvector(builder, p.users),
            //p2p::hashbuffermap_to_flatbuf_rawinputs(builder, p.raw_inputs),
            //p2p::stringlist_to_flatbuf_bytearrayvector(builder, p.hash_outputs)
        );

    builder.Finish(ledger); // Finished building message content to get serialised content.

    std::string_view ledger_str = p2p::flatbuff_bytes_to_sv(builder.GetBufferPointer(), fbuilder.GetSize());
    auto lcl = crypto::sha_512_hash(ledger, "LEDGER", 6);
    
    //save lcl
    std::string path;
    path.reserve(conf::ctx.histDir.size() + lcl.size());
    path.append(conf::ctx.histDir);
    path.append(lcl);
    
    std::ofstream ofs(move(path));
    ofs.write(ledger_str, ledger_str.size());
    ofs.close();
}

} // namespace cons