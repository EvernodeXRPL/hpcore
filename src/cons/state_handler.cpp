#include <flatbuffers/flatbuffers.h>
#include "state_handler.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/common_helpers.hpp"
#include "../p2p/p2p.hpp"
#include "../pchheader.hpp"
#include "../cons/cons.hpp"
#include "../statefs/state_store.hpp"

namespace cons
{

void request_state_from_peer(const std::string &path, bool &is_file, std::string &lcl, int32_t block_id = -1)
{
    p2p::state_request sr;
    sr.parent_path = path;
    sr.is_file = is_file;
    sr.block_id = block_id;
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
                fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(state_content_list, con_resp->content());

                std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
                std::string_view root_path_sv = fbschema::flatbuff_str_to_sv(con_resp->path());
                std::string root_path_str(root_path_sv.data(), root_path_sv.size());
                statefs::get_fsentry_hashes(existing_fs_entries, std::move(root_path_str));
                bool file_entry_found = false;

                for (const auto &[path, fs_entry] : existing_fs_entries)
                {

                    const auto fs_itr = state_content_list.find(path);
                    if (fs_itr != state_content_list.end())
                    {
                        if (fs_itr->second.hash != fs_entry.hash)
                            // request_state_from_peer(fs_itr->first, fs_itr->second.is_file, ctx.lcl);

                        state_content_list.erase(fs_itr);
                    }
                    else
                    {
                        if (fs_entry.is_file)
                            statefs::delete_file(path);
                        else
                            statefs::delete_folder(path);
                    }
                }

                for (const auto &[path, fs_entry] : state_content_list)
                {
                    request_state_from_peer(path, fs_entry.is_file, ctx.lcl);
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
            {
                const fbschema::p2pmsg::File_HashMap_Response *file_resp = resp_msg->state_response_as_File_HashMap_Response();

                std::vector<uint8_t> exising_block_hashmap;
                std::string_view path_sv = fbschema::flatbuff_str_to_sv(file_resp->path());
                const std::string path_str(path_sv.data(), path_sv.size());
                statefs::get_blockhashmap(exising_block_hashmap, std::move(path_str));

                const hasher::B2H *resp_b_hashmap = reinterpret_cast<const hasher::B2H *>(file_resp->hash_map());
                auto resp_hashmap_size = file_resp->hash_map()->size()/hasher::HASH_SIZE;
                if(exising_block_hashmap.size() > resp_hashmap_size )
                for (int i = 0; i < exising_block_hashmap.size(); ++i){

                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
            {
                const fbschema::p2pmsg::Block_Response *block_resp = resp_msg->state_response_as_Block_Response();
            }
        }
    }
}
} // namespace cons