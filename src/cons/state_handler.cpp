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

std::list<std::string> candidate_state_responses;

void request_state_from_peer(const std::string &path, bool is_file, std::string &lcl, int32_t block_id)
{
    p2p::state_request sr;
    sr.parent_path = path;
    sr.is_file = is_file;
    sr.block_id = block_id;
    p2p::peer_outbound_message msg(std::make_shared<flatbuffers::FlatBufferBuilder>(1024));
    fbschema::p2pmsg::create_msg_from_state_request(msg.builder(), sr, lcl);

    p2p::send_message_to_random_peer(msg);
}

p2p::peer_outbound_message send_state_response(p2p::state_request &sr)
{
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    if (sr.block_id > -1)
    {
        std::vector<uint8_t> blocks;
        statefs::get_block(blocks, sr.parent_path, sr.block_id);
        p2p::block_response resp;
        resp.path = sr.parent_path;
        resp.block_id = sr.block_id;
        resp.data = blocks;
        fbschema::p2pmsg::create_msg_from_block_response(msg.builder(), resp, ctx.lcl);
    }
    else
    {
        if (sr.is_file)
        {
            std::vector<uint8_t> existing_block_hashmap;
            statefs::get_blockhashmap(existing_block_hashmap, sr.parent_path);
            fbschema::p2pmsg::create_msg_from_filehashmap_response(msg.builder(), sr.parent_path, existing_block_hashmap, statefs::get_filelength(sr.parent_path), ctx.lcl);
        }
        else
        {
            std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
            statefs::get_fsentry_hashes(existing_fs_entries, sr.parent_path);
            fbschema::p2pmsg::create_msg_from_content_response(msg.builder(), sr.parent_path, existing_fs_entries, ctx.lcl);
        }
    }

    return msg;
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
                // fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(state_content_list, con_resp->content());

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
                            request_state_from_peer(path, fs_entry.is_file, ctx.lcl, -1);

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
                    request_state_from_peer(path, fs_entry.is_file, ctx.lcl, -1);
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
            {
                const fbschema::p2pmsg::File_HashMap_Response *file_resp = resp_msg->state_response_as_File_HashMap_Response();

                std::vector<uint8_t> exising_block_hashmap;
                std::string_view path_sv = fbschema::flatbuff_str_to_sv(file_resp->path());
                const std::string path_str(path_sv.data(), path_sv.size());
                statefs::get_blockhashmap(exising_block_hashmap, path_str);

                const std::vector<uint8_t> *resp_b_hashmap = reinterpret_cast<const std::vector<uint8_t> *>(file_resp->hash_map());
                auto resp_hashmap_size = file_resp->hash_map()->size() / hasher::HASH_SIZE;

                for (int i = 0; i < exising_block_hashmap.size(); ++i)
                {
                    if (i >= resp_hashmap_size)
                        break;

                    if (exising_block_hashmap[i] != *resp_b_hashmap[i].data())
                    {
                        request_state_from_peer(path_str, true, ctx.lcl, i);
                    }
                }

                if (exising_block_hashmap.size() > resp_hashmap_size)
                {
                    statefs::truncate_file(path_str, file_resp->file_length());
                }
                else if (exising_block_hashmap.size() < resp_hashmap_size)
                {
                    for (int i = (exising_block_hashmap.size() - 1); i < resp_hashmap_size; ++i)
                    {
                        request_state_from_peer(path_str, true, ctx.lcl, i);
                    }
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
            {
                p2p::block_response block_resp = fbschema::p2pmsg::create_block_response_from_msg(*resp_msg->state_response_as_Block_Response());
                statefs::write_block(block_resp.path, block_resp.block_id, block_resp.data.data(), block_resp.data.size());
            }
        }
    }
}
} // namespace cons