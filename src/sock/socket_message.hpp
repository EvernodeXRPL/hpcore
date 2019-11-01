#ifndef _HP_SOCKET_MESSAGE_H_
#define _HP_SOCKET_MESSAGE_H_

#include <flatbuffers/flatbuffers.h>
#include "../pchheader.hpp"

namespace sock
{

/**
 * Represents an outbound message that is sent with a websocket.
 * We use this class to wrap different object types holding actual message contents.
 * We use this mechanism to achieve end-to-end zero-copy between original message
 * content generator and websocket flush.
 */
class outbound_message
{
public:
    // Returns a pointer to the internal buffer owned by the message object.
    // Contents of this buffer is the message that is sent/received with the socket.
    virtual std::string_view buffer() = 0;
};

}

namespace usr
{

/**
 * Represents a message (bytes) that is sent to a user.
 */
class user_outbound_message : public sock::outbound_message
{
    // Contains message bytes.
    std::string msg;

public:
    user_outbound_message(std::string &&_msg);

    // Returns the buffer that should be written to the socket.
    virtual std::string_view buffer();
};

}

namespace p2p
{

/**
 * Represents a peer message generated using flatbuffer that must be sent to the socket.
 * We keep a shared_ptr of flatbuffer builder to support broadcasting the same message
 * on multiple connections without copying buffer contents.
 */
class peer_outbound_message : public sock::outbound_message
{
    std::shared_ptr<flatbuffers::FlatBufferBuilder> fbbuilder_ptr;

public:
    peer_outbound_message(std::shared_ptr<flatbuffers::FlatBufferBuilder> _fbbuilder_ptr);

    // Returns a reference to the flatbuffer builder object.
    flatbuffers::FlatBufferBuilder& builder();
    
    // Returns a reference to the data buffer that must be written to the socket.
    virtual std::string_view buffer();
};

}

#endif