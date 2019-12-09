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

constexpr uint16_t MAX_AWAITING_REQUESTS = 1;
constexpr uint16_t MAX_RESPONSE_WAIT_CYCLES = 100;

// List of state responses flatbuffer messages to be processed.
std::list<std::string> candidate_state_responses;

// List of pending sync requests to be sent out.
std::queue<backlog_item> pending_requests;

// List of submitted requests we are awaiting responses for, keyed by expected response hash.
std::unordered_map<hasher::B2H, backlog_item, hasher::B2H_std_key_hasher> submitted_requests;

void request_state_from_peer(const std::string &path, const bool is_file, const std::string &lcl, const int32_t block_id, const hasher::B2H expected_hash)
{
    p2p::state_request sr;
    sr.parent_path = path;
    sr.is_file = is_file;
    sr.block_id = block_id;
    sr.expected_hash = expected_hash;

    p2p::peer_outbound_message msg(std::make_unique<flatbuffers::FlatBufferBuilder>(1024));
    fbschema::p2pmsg::create_msg_from_state_request(msg.builder(), sr, lcl);
    p2p::send_message_to_random_peer(msg);
}

int create_state_response(p2p::peer_outbound_message &msg, const p2p::state_request &sr)
{
    if (sr.block_id > -1)
    {
        std::vector<uint8_t> blocks;

        if (statefs::get_block(blocks, sr.parent_path, sr.block_id, sr.expected_hash) == -1)
            return -1;

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

            if (statefs::get_block_hash_map(existing_block_hashmap, sr.parent_path, sr.expected_hash) == -1)
                return -1;

            fbschema::p2pmsg::create_msg_from_filehashmap_response(msg.builder(), sr.parent_path, existing_block_hashmap, statefs::get_file_length(sr.parent_path), sr.expected_hash, ctx.lcl);
        }
        else
        {
            std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;

            if (statefs::get_fs_entry_hashes(existing_fs_entries, sr.parent_path, sr.expected_hash) == -1)
                return -1;

            fbschema::p2pmsg::create_msg_from_fsentry_response(msg.builder(), sr.parent_path, existing_fs_entries, sr.expected_hash, ctx.lcl);
        }
    }

    return 0;
}

void start_state_sync(const hasher::B2H state_hash_to_request)
{
    std::cout << "start_state_sync() " << state_hash_to_request << "\n";

    {
        std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);
        p2p::ctx.collected_msgs.state_response.clear();
    }

    {
        std::lock_guard<std::mutex> lock(cons::ctx.state_syncing_mutex);
        candidate_state_responses.clear();
        std::queue<backlog_item>().swap(pending_requests);
        submitted_requests.clear();
    }

    // Send the root state request.
    submit_request(backlog_item{BACKLOG_ITEM_TYPE::DIR, "/", -1, state_hash_to_request});
}

int run_state_sync_iterator()
{
    while (true)
    {
        util::sleep(50);

        // TODO: Also bypass peer session handler responses if not syncing.
        if (!ctx.is_state_syncing)
            continue;

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

            // Check whether we are actually waiting for this response's hash. If not, ignore it.
            hasher::B2H response_hash = fbschema::flatbuff_bytes_to_hash(resp_msg->hash());
            const auto pending_resp_itr = submitted_requests.find(response_hash);
            if (pending_resp_itr == submitted_requests.end())
            {
                std::cout << "Ignoring state response.\n";
                continue;
            }

            // Now that we have received matching hash, remove it from the waiting list.
            submitted_requests.erase(pending_resp_itr);

            // Process the message based on response type.
            const fbschema::p2pmsg::State_Response msg_type = resp_msg->state_response_type();

            if (msg_type == fbschema::p2pmsg::State_Response_Fs_Entry_Response)
            {
                if (handle_fs_entry_response(resp_msg->state_response_as_Fs_Entry_Response()) == -1)
                    return -1;
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_File_HashMap_Response)
            {
                if (handle_file_hashmap_response(resp_msg->state_response_as_File_HashMap_Response()) == -1)
                    return -1;
            }
            else if (msg_type == fbschema::p2pmsg::State_Response_Block_Response)
            {
                if (handle_file_block_response(resp_msg->state_response_as_Block_Response()) == -1)
                    return -1;
            }
        }

        candidate_state_responses.clear();

        // Check for long-awaited responses and re-request them.
        for (auto &[hash, request] : submitted_requests)
        {
            if (request.waiting_cycles < MAX_RESPONSE_WAIT_CYCLES)
            {
                // Increment counter.
                request.waiting_cycles++;
            }
            else
            {
                // Reset the counter and re-submit request.
                request.waiting_cycles = 0;
                std::cout << "Resubmit state request\n";
                submit_request(request);
            }
        }

        // Check whether we can submit any more requests.
        if (!pending_requests.empty() && submitted_requests.size() < MAX_AWAITING_REQUESTS)
        {
            const uint16_t available_slots = MAX_AWAITING_REQUESTS - submitted_requests.size();
            for (int i = 0; i < available_slots; i++)
            {
                const backlog_item &request = pending_requests.front();
                submit_request(request);
                pending_requests.pop();
            }
        }
    }

    return 0;
}

void submit_request(const backlog_item &request)
{
    std::cout << "Submitting state request. type: " << request.type << " path:" << request.path << " blockid: " << request.block_id << "\n";

    submitted_requests.try_emplace(request.expected_hash, request);

    const bool is_file = request.type != BACKLOG_ITEM_TYPE::DIR;
    request_state_from_peer(request.path, is_file, ctx.lcl, request.block_id, request.expected_hash);
}

int handle_fs_entry_response(const fbschema::p2pmsg::Fs_Entry_Response *fs_entry_resp)
{
    std::cout << "Recieved state fs entry response\n";

    std::unordered_map<std::string, p2p::state_fs_hash_entry> state_fs_entry_list;
    fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(state_fs_entry_list, fs_entry_resp->entries());

    for (const auto [a, b] : state_fs_entry_list)
        std::cout << "Recieved fsentry: " << a << "\n";

    std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
    std::string_view root_path_sv = fbschema::flatbuff_str_to_sv(fs_entry_resp->path());
    std::string root_path_str(root_path_sv.data(), root_path_sv.size());

    if (!statefs::is_dir_exists(root_path_str))
    {
        statefs::create_dir(root_path_str);
    }
    else
    {
        if (statefs::get_fs_entry_hashes(existing_fs_entries, std::move(root_path_str), hasher::B2H_empty) == -1)
            return -1;
    }

    // Request more info on fs entries that exist on both sides but are different.
    for (const auto &[path, fs_entry] : existing_fs_entries)
    {
        std::cout << "Existing path :" << path << std::endl;
        const auto fs_itr = state_fs_entry_list.find(path);
        if (fs_itr != state_fs_entry_list.end())
        {
            std::cout << "Existing fs_entry_hash :" << fs_entry.hash << std::endl;
            std::cout << "Recieved fs_entry_hash :" << fs_itr->second.hash << std::endl;
            if (fs_itr->second.hash != fs_entry.hash)
            {
                pending_requests.push(
                    backlog_item{
                        fs_entry.is_file ? BACKLOG_ITEM_TYPE::FILE : BACKLOG_ITEM_TYPE::DIR,
                        path,
                        -1,
                        fs_itr->second.hash});
            }

            state_fs_entry_list.erase(fs_itr);
        }
        else
        {
            // If there was an entry that does not exist on other side, delete it from this node.
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

    // Queue the remaining fs entries (that this node does not have at all) to request.
    for (const auto &[path, fs_entry] : state_fs_entry_list)
    {
        pending_requests.push(
            backlog_item{
                fs_entry.is_file ? BACKLOG_ITEM_TYPE::FILE : BACKLOG_ITEM_TYPE::DIR,
                path,
                -1,
                fs_entry.hash});
    }

    return 0;
}

int handle_file_hashmap_response(const fbschema::p2pmsg::File_HashMap_Response *file_resp)
{
    std::string_view path_sv = fbschema::flatbuff_str_to_sv(file_resp->path());
    const std::string path_str(path_sv.data(), path_sv.size());

    std::cout << "Recieved file hash map of " << path_str << std::endl;

    std::vector<uint8_t> existing_block_hashmap;
    if (statefs::get_block_hash_map(existing_block_hashmap, path_str, hasher::B2H_empty) == -1)
        return -1;

    const hasher::B2H *existing_hashes = reinterpret_cast<const hasher::B2H *>(existing_block_hashmap.data());
    auto existing_hash_count = existing_block_hashmap.size() / hasher::HASH_SIZE;

    const hasher::B2H *resp_hashes = reinterpret_cast<const hasher::B2H *>(file_resp->hash_map()->data());
    auto resp_hash_count = file_resp->hash_map()->size() / hasher::HASH_SIZE;

    std::cout << "Reieved file hashmap size :" << file_resp->hash_map()->size() << std::endl;
    std::cout << "Existing file hashmap size :" << existing_block_hashmap.size() << std::endl;

    for (int block_id = 0; block_id < existing_hash_count; ++block_id)
    {
        if (block_id >= resp_hash_count)
            break;

        if (existing_hashes[block_id] != resp_hashes[block_id])
        {
            std::cout << "Mismatch in file block  :" << block_id << std::endl;
            pending_requests.push(backlog_item{BACKLOG_ITEM_TYPE::BLOCK, path_str, block_id, resp_hashes[block_id]});
        }
    }

    if (existing_hash_count > resp_hash_count)
    {
        if (statefs::truncate_file(path_str, file_resp->file_length()) == -1)
            return -1;
    }
    else if (existing_hash_count < resp_hash_count)
    {
        for (int block_id = existing_hash_count; block_id < resp_hash_count; ++block_id)
        {
            std::cout << "Missing block: " << block_id << "\n";
            pending_requests.push(backlog_item{BACKLOG_ITEM_TYPE::BLOCK, path_str, block_id, resp_hashes[block_id]});
        }
    }

    return 0;
}

int handle_file_block_response(const fbschema::p2pmsg::Block_Response *block_msg)
{
    p2p::block_response block_resp = fbschema::p2pmsg::create_block_response_from_msg(*block_msg);

    std::cout << "Recieved block " << block_resp.block_id << " of " << block_resp.path << "\n";

    if (statefs::write_block(block_resp.path, block_resp.block_id, block_resp.data.data(), block_resp.data.size()) == -1)
        return -1;

    return 0;
}

} // namespace cons