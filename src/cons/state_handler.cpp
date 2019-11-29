#include <flatbuffers/flatbuffers.h>
#include "state_handler.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../p2p/p2p.hpp"
#include "../pchheader.hpp"
#include "../cons/cons.hpp"

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
    if (sr.block_id > -1)
    {
    }
    else
    {
    }
}

void handle_state_response()
{
    while (true)
    {

        {
            std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);
            candidate_state_responses.clear();
            auto it = p2p::ctx.collected_msgs.state_response.begin();
            candidate_state_responses.splice(candidate_state_responses.end(), p2p::ctx.collected_msgs.state_response, it);
        }

        if (candidate_state_responses.empty())
            continue;

        if (candidate_state_responses.size() > 1)
        {
            LOG_DBG << "Invalid number of state responses to process";
        }

        for (auto &response : candidate_state_responses)
        {
            const fbschema::p2pmsg::Content *content = fbschema::p2pmsg::GetContent(response.data());
            const fbschema::p2pmsg::State_Response_Message *resp_msg = content->message_as_State_Response_Message();

            const fbschema::p2pmsg::State_Response msg_type = resp_msg->state_response_type();
            if (msg_type == fbschema::p2pmsg::State_Response_Content_Response)
            {
                const fbschema::p2pmsg::Content_Response *con_resp = resp_msg->state_response_as_Content_Response();
                std::unordered_map<std::string, p2p::state_fs_hash_entry> state_content_list;

                 std::unordered_map<std::string, p2p::state_fs_hash_entry> &&l = fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(con_resp->content());
                state_content_list.swap(l);

                std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
                bool file_entry_found = false;
               
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
            {
                const fbschema::p2pmsg::File_HashMap_Response *file_resp = resp_msg->state_response_as_File_HashMap_Response();
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
            {
                const fbschema::p2pmsg::Block_Response *block_resp = resp_msg->state_response_as_Block_Response();
            }
        }
    }
}
} // namespace cons