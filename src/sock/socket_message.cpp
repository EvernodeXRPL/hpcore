#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"
#include "socket_message.hpp"

namespace p2p
{

peer_outbound_message::peer_outbound_message(
    std::shared_ptr<flatbuffers::FlatBufferBuilder> fbbuilder_ptr)
{
    this->fbbuilder_ptr = fbbuilder_ptr;
}

// Returns a reference to the flatbuffer builder object.
flatbuffers::FlatBufferBuilder &peer_outbound_message::builder()
{
    return *fbbuilder_ptr;
}

// Returns a reference to the data buffer that must be written to the socket.
std::string_view peer_outbound_message::buffer()
{
    return std::string_view(
        reinterpret_cast<const char *>(fbbuilder_ptr->GetBufferPointer()),
        fbbuilder_ptr->GetSize());
}

}