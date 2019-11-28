#include <flatbuffers/flatbuffers.h>
#include "state_handler.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../p2p/p2p.hpp"

namespace cons
{

void request_state_from_peer(std::string &path, std::string &lcl)
{
    p2p::state_request sr;
    sr.parent_path = path;
    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    fbschema::p2pmsg::create_msg_from_state_request(msg.builder(), sr, lcl);

    p2p::send_message_to_random_peer(msg);
}

void send_state_response(p2p::state_request &sr)
{
    if(sr.block_id > -1){

    }else{
        
    }
}

void handle_state_response(){
    
}
} // namespace cons