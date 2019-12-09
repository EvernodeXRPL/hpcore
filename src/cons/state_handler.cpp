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

// The file currently being processed.
std::string processing_file;

// Current block of the current file being processed.
int32_t processing_block_id = -1;

// Map of file/dir paths and whether file or dir flag.
std::map<std::string, bool> paths_to_request;

// Map of file paths and the set of block ids to request.
std::map<std::string, std::set<uint32_t>> blocks_to_request;

// Map of file paths and set of block ids to be written to disk.
std::map<std::string, std::set<uint32_t>> blocks_to_write;

void request_state_from_peer(const std::string &path, bool is_file, std::string &lcl, int32_t block_id)
{
    p2p::state_request sr;
    sr.parent_path = path;
    sr.is_file = is_file;
    sr.block_id = block_id;
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    fbschema::p2pmsg::create_msg_from_state_request(msg.builder(), sr, lcl);
    p2p::send_message_to_random_peer(msg);
}

p2p::peer_outbound_message send_state_response(const p2p::state_request &sr)
{
    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    if (sr.block_id > -1)
    {
        std::vector<uint8_t> blocks;

        if (statefs::get_block(blocks, sr.parent_path, sr.block_id) == -1)
            return msg;

        p2p::block_response resp;
        resp.path = sr.parent_path;
        resp.block_id = sr.block_id;
        resp.hash = sr.expected_hash;

        resp.data = std::string_view(reinterpret_cast<const char *>(blocks.data()), blocks.size());
        fbschema::p2pmsg::create_msg_from_block_response(msg.builder(), resp, ctx.lcl);
    }
    else
    {
        if (sr.is_file)
        {
            std::vector<uint8_t> existing_block_hashmap;

            if (statefs::get_block_hash_map(existing_block_hashmap, sr.parent_path) == -1)
                return msg;

            fbschema::p2pmsg::create_msg_from_filehashmap_response(msg.builder(), sr.parent_path, existing_block_hashmap, statefs::get_file_length(sr.parent_path), sr.expected_hash, ctx.lcl);
        }
        else
        {
            std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;

            if (statefs::get_fs_entry_hashes(existing_fs_entries, sr.parent_path) == -1)
                return msg;

            fbschema::p2pmsg::create_msg_from_content_response(msg.builder(), sr.parent_path, existing_fs_entries, sr.expected_hash,ctx.lcl);
        }
    }

    return msg;
}

void reset_state_sync()
{
    std::cout << "reset_state_sync()\n";

    std::lock_guard<std::mutex> lock(cons::ctx.state_syncing_mutex);
    {
        candidate_state_responses.clear();
        processing_file.clear();
        processing_block_id = -1;
        paths_to_request.clear();
        blocks_to_request.clear();
        blocks_to_write.clear();
    }
}

int handle_state_response()
{
    while (true)
    {
        util::sleep(50);

        {
            std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);

            // Move collected state responses over to local candidate responses list.
            if (!p2p::ctx.collected_msgs.state_response.empty())
                candidate_state_responses.splice(candidate_state_responses.end(), p2p::ctx.collected_msgs.state_response);
        }

        std::lock_guard<std::mutex> lock(cons::ctx.state_syncing_mutex);

        for (auto &response : candidate_state_responses)
        {
            const fbschema::p2pmsg::Content *content = fbschema::p2pmsg::GetContent(response.data());
            const fbschema::p2pmsg::State_Response_Message *resp_msg = content->message_as_State_Response_Message();

            const fbschema::p2pmsg::State_Response msg_type = resp_msg->state_response_type();
            if (msg_type == fbschema::p2pmsg::State_Response_Content_Response)
            {
                std::cout << "Recieved state fs entry response\n";

                const fbschema::p2pmsg::Content_Response *con_resp = resp_msg->state_response_as_Content_Response();
                std::unordered_map<std::string, p2p::state_fs_hash_entry> state_content_list;
                fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(state_content_list, con_resp->content());

                for (const auto [a, b] : state_content_list)
                    std::cout << "Recieved fsentry: " << a << "\n";

                std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
                std::string_view root_path_sv = fbschema::flatbuff_str_to_sv(con_resp->path());
                std::string root_path_str(root_path_sv.data(), root_path_sv.size());

                if (!statefs::is_dir_exists(root_path_str))
                {
                    statefs::create_dir(root_path_str);
                }
                else
                {
                    if (statefs::get_fs_entry_hashes(existing_fs_entries, std::move(root_path_str)) == -1)
                        return -1;
                }

                for (const auto &[path, fs_entry] : existing_fs_entries)
                {
                    std::cout << "Existing path :" << path << std::endl;
                    const auto fs_itr = state_content_list.find(path);
                    if (fs_itr != state_content_list.end())
                    {
                        std::cout << "Existing fs_entry_hash :" << fs_entry.hash << std::endl;
                        std::cout << "Recieved fs_entry_hash :" << fs_itr->second.hash << std::endl;
                        if (fs_itr->second.hash != fs_entry.hash)
                            paths_to_request.try_emplace(path, fs_entry.is_file);

                        state_content_list.erase(fs_itr);
                    }
                    else
                    {
                        if (fs_entry.is_file)
                        {
                            if (statefs::delete_file(path) == -1)
                                return -1;
                        }
                        else
                        {
                            if (statefs::delete_dir(path) == -1)
                                return -1;
                        }
                    }
                }

                for (const auto &[path, fs_entry] : state_content_list)
                {
                    paths_to_request.try_emplace(path, fs_entry.is_file);
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
            {
                std::cout << "Recieved state hash map response" << std::endl;
                const fbschema::p2pmsg::File_HashMap_Response *file_resp = resp_msg->state_response_as_File_HashMap_Response();

                std::vector<uint8_t> exising_block_hashmap;
                std::string_view path_sv = fbschema::flatbuff_str_to_sv(file_resp->path());
                const std::string path_str(path_sv.data(), path_sv.size());

                if (statefs::get_block_hash_map(exising_block_hashmap, path_str) == -1)
                    return -1;

                const hasher::B2H *existing_hashes = reinterpret_cast<const hasher::B2H *>(exising_block_hashmap.data());
                auto existing_hash_count = exising_block_hashmap.size() / hasher::HASH_SIZE;

                const hasher::B2H *resp_hashes = reinterpret_cast<const hasher::B2H *>(file_resp->hash_map()->data());
                auto resp_hash_count = file_resp->hash_map()->size() / hasher::HASH_SIZE;

                std::cout << "Reieved file hashmap size :" << file_resp->hash_map()->size() << std::endl;
                std::cout << "Existing file hashmap size :" << exising_block_hashmap.size() << std::endl;

                std::set<uint32_t> blockids_to_request;

                for (int i = 0; i < existing_hash_count; ++i)
                {
                    if (i >= resp_hash_count)
                        break;

                    if (existing_hashes[i] != resp_hashes[i])
                    {
                        std::cout << "Mismatch in file block  :" << i << std::endl;
                        blockids_to_request.emplace(i);
                    }
                }

                if (existing_hash_count > resp_hash_count)
                {
                    if (statefs::truncate_file(path_str, file_resp->file_length()) == -1)
                        return -1;
                }
                else if (existing_hash_count < resp_hash_count)
                {
                    for (int i = existing_hash_count; i < resp_hash_count; ++i)
                    {
                        std::cout << "Missing block: " << i << "\n";
                        blockids_to_request.emplace(i);
                    }
                }

                if (!blockids_to_request.empty())
                {
                    // Copy the requesting block ids into list of blocks to be written.
                    blocks_to_write[path_str] = blockids_to_request;

                    blocks_to_request[path_str] = std::move(blockids_to_request);
                }
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
            {
                std::cout << "Recieved state block response";
                p2p::block_response block_resp = fbschema::p2pmsg::create_block_response_from_msg(*resp_msg->state_response_as_Block_Response());

                if (statefs::write_block(block_resp.path, block_resp.block_id, block_resp.data.data(), block_resp.data.size()) == -1)
                    return -1;

                processing_block_id = -1;
                std::set<uint32_t> &remaining_blocks = blocks_to_write[block_resp.path];
                remaining_blocks.erase(block_resp.block_id);

                // If no more remaining blocks to be written, this means we have fully reconstructed the file.
                if (remaining_blocks.empty())
                {
                    blocks_to_write.erase(block_resp.path);
                    std::cout << "remaining_blocks empty processing_file.clear()\n";
                    processing_file.clear();
                }
            }
        }

        candidate_state_responses.clear();

        if (processing_file.empty())
        {
            if (!paths_to_request.empty())
            {
                // Choose the next item from the paths to be requested.
                const auto itr = paths_to_request.begin();
                const std::string &path_to_request = itr->first;
                const bool is_file = itr->second;
                std::cout << "Sending request to path_to_request " << path_to_request << "  isfile:" << is_file << "\n";
                request_state_from_peer(path_to_request, is_file, ctx.lcl, -1);

                if (is_file)
                    processing_file = path_to_request;

                paths_to_request.erase(itr);
            }
        }
        else if (processing_block_id == -1)
        {
            // Check whether we know which blocks to request for the file being processed.
            const auto itr = blocks_to_request.find(processing_file);
            if (itr != blocks_to_request.end())
            {
                std::set<uint32_t> &remaining_blocks = itr->second;

                // Send a request to the first block in the remaining list.
                const uint32_t block_to_request = *remaining_blocks.begin();
                std::cout << "Sending request to block_to_request: " << block_to_request << "\n";
                request_state_from_peer(processing_file, true, ctx.lcl, block_to_request);
                remaining_blocks.erase(block_to_request);

                // If we have requested all the blocks by now, clear the map entry as well.
                if (remaining_blocks.empty())
                    blocks_to_request.erase(itr);

                processing_block_id = block_to_request;
                std::cout << "processing_block_id: " << processing_block_id << "\n";
            }
        }
    }

    return 0;
}
} // namespace cons