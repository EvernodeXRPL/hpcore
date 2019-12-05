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
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    fbschema::p2pmsg::create_msg_from_state_request(msg.builder(), sr, lcl);
    std::cout << "Sending state sync request" << std::endl;
    p2p::send_message_to_random_peer(msg);
}

p2p::peer_outbound_message send_state_response(const p2p::state_request &sr)
{
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    if (sr.block_id > -1)
    {
        std::cout << "Recieved block request" << std::endl;
        std::vector<uint8_t> blocks;

        if (statefs::get_block(blocks, sr.parent_path, sr.block_id) == -1)
            return;

        p2p::block_response resp;
        resp.path = sr.parent_path;
        resp.block_id = sr.block_id;

        resp.data = std::string_view(reinterpret_cast<const char *>(blocks.data()), blocks.size());
        fbschema::p2pmsg::create_msg_from_block_response(msg.builder(), resp, ctx.lcl);
    }
    else
    {
        if (sr.is_file)
        {
            std::cout << "Recieved filehashmap request" << std::endl;
            std::vector<uint8_t> existing_block_hashmap;

            if (statefs::get_blockhashmap(existing_block_hashmap, sr.parent_path) == -1)
                return;

            fbschema::p2pmsg::create_msg_from_filehashmap_response(msg.builder(), sr.parent_path, existing_block_hashmap, statefs::get_filelength(sr.parent_path), ctx.lcl);
        }
        else
        {
            std::cout << "Recieved state content request" << std::endl;
            std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;

            if (statefs::get_fsentry_hashes(existing_fs_entries, sr.parent_path) == -1)
                return;

            fbschema::p2pmsg::create_msg_from_content_response(msg.builder(), sr.parent_path, existing_fs_entries, ctx.lcl);
        }
    }

    return msg;
}

void handle_state_response()
{
    while (true)
    {
        util::sleep(100);

        std::lock_guard<std::mutex> lock(cons::ctx.state_syncing_mutex);
        {
            std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);

            if (p2p::ctx.collected_msgs.state_response.empty())
                continue;

            candidate_state_responses.clear();

            auto it = p2p::ctx.collected_msgs.state_response.begin();
            candidate_state_responses.splice(candidate_state_responses.end(), p2p::ctx.collected_msgs.state_response, it);
        }

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
                LOG_DBG << "Recieved state content response";
                const fbschema::p2pmsg::Content_Response *con_resp = resp_msg->state_response_as_Content_Response();
                std::unordered_map<std::string, p2p::state_fs_hash_entry> state_content_list;
                fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(state_content_list, con_resp->content());

                for (const auto [a, b] : state_content_list)
                    std::cout << "**********Recieved fsentry: " << a << "\n";

                std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
                std::string_view root_path_sv = fbschema::flatbuff_str_to_sv(con_resp->path());
                std::string root_path_str(root_path_sv.data(), root_path_sv.size());

                if (statefs::get_fsentry_hashes(existing_fs_entries, std::move(root_path_str)) == -1)
                    return;

                for (const auto &[path, fs_entry] : existing_fs_entries)
                {
                    std::cout << "Existing path :" << path << std::endl;
                    const auto fs_itr = state_content_list.find(path);
                    if (fs_itr != state_content_list.end())
                    {
                        std::cout << "Existing fs_entry_hash :" << fs_entry.hash << std::endl;
                        std::cout << "Recieved fs_entry_hash :" << fs_itr->second.hash << std::endl;
                        if (fs_itr->second.hash != fs_entry.hash)
                            request_state_from_peer(path, fs_entry.is_file, ctx.lcl, -1);

                        state_content_list.erase(fs_itr);
                    }
                    else
                    {
                        if (fs_entry.is_file)
                        {
                            if (statefs::delete_file(path) == -1)
                                return;
                        }
                        else
                        {
                            if (statefs::delete_folder(path) == -1)
                                return;
                        }
                    }
                }

                for (const auto &[path, fs_entry] : state_content_list)
                {
                    request_state_from_peer(path, fs_entry.is_file, ctx.lcl, -1);
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
            {
                std::cout << "Recieved state hash map response" << std::endl;
                LOG_DBG << "Recieved state hash map response";
                const fbschema::p2pmsg::File_HashMap_Response *file_resp = resp_msg->state_response_as_File_HashMap_Response();

                std::vector<uint8_t> exising_block_hashmap;
                std::string_view path_sv = fbschema::flatbuff_str_to_sv(file_resp->path());
                const std::string path_str(path_sv.data(), path_sv.size());

                if (statefs::get_blockhashmap(exising_block_hashmap, path_str) == -1)
                    return;

                const hasher::B2H *existing_hashes = reinterpret_cast<const hasher::B2H *>(exising_block_hashmap.data());
                auto existing_hash_count = exising_block_hashmap.size() / hasher::HASH_SIZE;

                const hasher::B2H *resp_hashes = reinterpret_cast<const hasher::B2H *>(file_resp->hash_map()->data());
                auto resp_hash_count = file_resp->hash_map()->size() / hasher::HASH_SIZE;

                std::cout << "Reieved file hashmap size :" << file_resp->hash_map()->size() << std::endl;
                std::cout << "Existing file hashmap size :" << exising_block_hashmap.size() << std::endl;
                for (int i = 0; i < existing_hash_count; ++i)
                {
                    if (i >= resp_hash_count)
                        break;

                    if (existing_hashes[i] != resp_hashes[i])
                    {
                        std::cout << "Mismatch in file block  :" << i << std::endl;
                        request_state_from_peer(path_str, true, ctx.lcl, i);
                    }
                }

                if (existing_hash_count > resp_hash_count)
                {
                    if (statefs::truncate_file(path_str, file_resp->file_length()) == -1)
                        return;
                }
                else if (existing_hash_count < resp_hash_count)
                {
                    for (int i = existing_hash_count; i < resp_hash_count; ++i)
                    {
                        request_state_from_peer(path_str, true, ctx.lcl, i);
                    }
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
            {
                std::cout << "Recieved state block response" << std::endl;
                LOG_DBG << "Recieved state block response";
                p2p::block_response block_resp = fbschema::p2pmsg::create_block_response_from_msg(*resp_msg->state_response_as_Block_Response());
                std::cout << "AAAA" << std::endl;

                if (statefs::write_block(block_resp.path, block_resp.block_id, block_resp.data.data(), block_resp.data.size()) == -1)
                    return;
            }
        }
    }
}
} // namespace cons