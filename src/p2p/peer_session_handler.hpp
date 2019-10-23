#ifndef _HP_PEER_SESSION_HANDLER_H_
#define _HP_PEER_SESSION_HANDLER_H_

#include <boost/beast/core.hpp>
#include <flatbuffers/flatbuffers.h>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

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

class peer_session_handler : public sock::socket_session_handler<peer_outbound_message>
{
public:
    void on_connect(sock::socket_session<peer_outbound_message> *session);

    void on_message(sock::socket_session<peer_outbound_message> *session, std::string_view message);

    void on_close(sock::socket_session<peer_outbound_message> *session);
};

} // namespace p2p
#endif