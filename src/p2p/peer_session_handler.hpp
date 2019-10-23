#ifndef _HP_P2P_SESSION_H_
#define _HP_P2P_SESSION_H_

#include <boost/beast/core.hpp>
#include <flatbuffers/flatbuffers.h>
#include "../sock/socket_session_handler.hpp"
#include "../sock/socket_session.hpp"

namespace p2p
{

class peer_outbound_message : public sock::outbound_message
{
    std::shared_ptr<flatbuffers::FlatBufferBuilder> fbbuilder_ptr;

public:
    peer_outbound_message(std::shared_ptr<flatbuffers::FlatBufferBuilder> _fbbuilder_ptr);

    flatbuffers::FlatBufferBuilder& builder();
    
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