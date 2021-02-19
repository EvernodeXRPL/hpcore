#ifndef _HP_MSG_FBUF_P2PMSG_CONVERSION_
#define _HP_MSG_FBUF_P2PMSG_CONVERSION_

#include "../../pchheader.hpp"
#include "../../p2p/p2p.hpp"
#include "p2pmsg_generated.h"

namespace msg::fbuf2::p2pmsg
{

    //---Flatbuf to std---//

    const std::set<std::string>
    flatbuf_bytearrayvector_to_stringlist(const flatbuffers::Vector<flatbuffers::Offset<ByteArray>> *fbvec);


    //---std to Flatbuf---//

    const flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<ByteArray>>>
    stringlist_to_flatbuf_bytearrayvector(flatbuffers::FlatBufferBuilder &builder, const std::set<std::string> &set);
}

#endif
