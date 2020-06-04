#include "state_handler.hpp"
#include "../fbschema/p2pmsg_helpers.hpp"
#include "../fbschema/p2pmsg_content_generated.h"
#include "../fbschema/common_helpers.hpp"
#include "../p2p/p2p.hpp"
#include "../pchheader.hpp"
#include "../cons/cons.hpp"
#include "../hplog.hpp"
#include "../util.hpp"

namespace cons
{

// Max number of requests that can be awaiting response at any given time.
constexpr uint16_t MAX_AWAITING_REQUESTS = 1;
// Syncing loop sleep delay.
constexpr uint16_t SYNC_LOOP_WAIT = 100;

// List of state responses flatbuffer messages to be processed.
std::list<std::string> candidate_state_responses;

// List of pending sync requests to be sent out.
std::list<backlog_item> pending_requests;

// List of submitted requests we are awaiting responses for, keyed by expected response hash.
std::unordered_map<hpfs::h32, backlog_item, hpfs::h32_std_key_hasher> submitted_requests;

/**
 * Sends a state request to a random peer.
 * @param path Requested file or dir path.
 * @param is_file Whether the requested path if a file or dir.
 * @param block_id The requested block id. Only relevant if requesting a file block. Otherwise -1.
 * @param expected_hash The expected hash of the requested data. The peer will ignore the request if their hash is different.
 */
void request_state_from_peer(const std::string &path, const bool is_file, const int32_t block_id, const hpfs::h32 expected_hash)
{
    p2p::state_request sr;
    sr.parent_path = path;
    sr.is_file = is_file;
    sr.block_id = block_id;
    sr.expected_hash = expected_hash;

    flatbuffers::FlatBufferBuilder fbuf(1024);
    fbschema::p2pmsg::create_msg_from_state_request(fbuf, sr, ctx.lcl);
    p2p::send_message_to_random_peer(fbuf); //todo: send to a node that hold the majority state to improve reliability of retrieving state.
}

/**
 * Creats the reply message for a given state request.
 * @param msg The peer outbound message reference to build up the reply message.
 * @param sr The state request which should be replied to.
 */
int create_state_response(flatbuffers::FlatBufferBuilder &fbuf, const p2p::state_request &sr)
{
    // If block_id > -1 this means this is a file block data request.
    if (sr.block_id > -1)
    {
        // Vector to hold the block bytes. Normally block size is constant BLOCK_SIZE (4MB), but the
        // last block of a file may have a smaller size.
        std::vector<uint8_t> block;
        
        // TODO: get block

        p2p::block_response resp;
        resp.path = sr.parent_path;
        resp.block_id = sr.block_id;
        resp.hash = sr.expected_hash;
        resp.data = std::string_view(reinterpret_cast<const char *>(block.data()), block.size());

        fbschema::p2pmsg::create_msg_from_block_response(fbuf, resp, ctx.lcl);
    }
    else
    {
        // File state request means we have to reply with the file block hash map.
        if (sr.is_file)
        {
            std::vector<uint8_t> existing_block_hashmap;
            
            // TODO: get block hash list
            // TODO: get file length
            std::size_t file_length = 0;

            fbschema::p2pmsg::create_msg_from_filehashmap_response(fbuf, sr.parent_path, existing_block_hashmap, file_length, sr.expected_hash, ctx.lcl);
        }
        else
        {
            // If the state request is for a directory we need to reply with the file system entries and their hashes inside that dir.
            std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
            
            // TODO: get fs entry hashes

            fbschema::p2pmsg::create_msg_from_fsentry_response(fbuf, sr.parent_path, existing_fs_entries, sr.expected_hash, ctx.lcl);
        }
    }

    return 0;
}

/**
 * Initiates state sync process by setting up context variables and sending the initial state request.
 * @param state_hash_to_request Peer's expected state hash. If peer doesn't have this as its state hash the
 *                              request will be ignord.
 */
void start_state_sync(const hpfs::h32 state_hash_to_request)
{
    {
        std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);
        p2p::ctx.collected_msgs.state_response.clear();
    }

    {
        candidate_state_responses.clear();
        pending_requests.clear();
        submitted_requests.clear();
    }

    // Send the root state request.
    submit_request(backlog_item{BACKLOG_ITEM_TYPE::DIR, "/", -1, state_hash_to_request});
}

/**
 * Runs the state sync loop.
 */
int run_state_sync_iterator()
{
    util::mask_signal();

    while (true)
    {
        if (ctx.is_shutting_down)
            break;

        util::sleep(SYNC_LOOP_WAIT);

        // TODO: Also bypass peer session handler state responses if we're not syncing.

        {
            std::lock_guard<std::mutex> lock(p2p::ctx.collected_msgs.state_response_mutex);

            // Move collected state responses over to local candidate responses list.
            if (!p2p::ctx.collected_msgs.state_response.empty())
                candidate_state_responses.splice(candidate_state_responses.end(), p2p::ctx.collected_msgs.state_response);
        }

        for (auto &response : candidate_state_responses)
        {
            if (ctx.is_shutting_down)
                break;

            const fbschema::p2pmsg::Content *content = fbschema::p2pmsg::GetContent(response.data());
            const fbschema::p2pmsg::State_Response_Message *resp_msg = content->message_as_State_Response_Message();

            // Check whether we are actually waiting for this response's hash. If not, ignore it.
            hpfs::h32 response_hash = fbschema::flatbuff_bytes_to_hash(resp_msg->hash());
            const auto pending_resp_itr = submitted_requests.find(response_hash);
            if (pending_resp_itr == submitted_requests.end())
                continue;

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
            if (ctx.is_shutting_down)
                break;

            // We wait for half of round time before each request is resubmitted.
            if (request.waiting_cycles < (conf::cfg.roundtime / (SYNC_LOOP_WAIT * 2)))
            {
                // Increment counter.
                request.waiting_cycles++;
            }
            else
            {
                // Reset the counter and re-submit request.
                request.waiting_cycles = 0;
                LOG_DBG << "Resubmitting state request...";
                submit_request(request);
            }
        }

        // Check whether we can submit any more requests.
        if (!pending_requests.empty() && submitted_requests.size() < MAX_AWAITING_REQUESTS)
        {
            const uint16_t available_slots = MAX_AWAITING_REQUESTS - submitted_requests.size();
            for (int i = 0; i < available_slots && !pending_requests.empty(); i++)
            {
                if (ctx.is_shutting_down)
                    break;
                    
                const backlog_item &request = pending_requests.front();
                submit_request(request);
                pending_requests.pop_front();
            }
        }
    }

    return 0;
}

/**
 * Submits a pending state request to the peer.
 */
void submit_request(const backlog_item &request)
{
    LOG_DBG << "Submitting state request. type:" << request.type << " path:" << request.path << " block_id:" << request.block_id;

    submitted_requests.try_emplace(request.expected_hash, request);

    const bool is_file = request.type != BACKLOG_ITEM_TYPE::DIR;
    request_state_from_peer(request.path, is_file, request.block_id, request.expected_hash);
}

/**
 * Process state file system entry response for a directory.
 */
int handle_fs_entry_response(const fbschema::p2pmsg::Fs_Entry_Response *fs_entry_resp)
{
    std::unordered_map<std::string, p2p::state_fs_hash_entry> state_fs_entry_list;
    fbschema::p2pmsg::flatbuf_statefshashentry_to_statefshashentry(state_fs_entry_list, fs_entry_resp->entries());

    std::unordered_map<std::string, p2p::state_fs_hash_entry> existing_fs_entries;
    std::string_view root_path_sv = fbschema::flatbuff_str_to_sv(fs_entry_resp->path());
    std::string root_path_str(root_path_sv.data(), root_path_sv.size());

    // TODO: Create state path dir if not exist.
    // TODO: Get existing fs entries hash map.
    // if (!statefs::is_dir_exists(root_path_str))
    // {
    //     statefs::create_dir(root_path_str);
    // }
    // else
    // {
    //     if (statefs::get_fs_entry_hashes(existing_fs_entries, std::move(root_path_str), hpfs::h32_empty) == -1)
    //         return -1;
    // }

    // Request more info on fs entries that exist on both sides but are different.
    for (const auto &[path, fs_entry] : existing_fs_entries)
    {
        const auto fs_itr = state_fs_entry_list.find(path);
        if (fs_itr != state_fs_entry_list.end())
        {
            if (fs_itr->second.hash != fs_entry.hash)
            {
                if (fs_entry.is_file)
                    pending_requests.push_front(backlog_item{BACKLOG_ITEM_TYPE::FILE, path, -1, fs_itr->second.hash});
                else
                    pending_requests.push_back(backlog_item{BACKLOG_ITEM_TYPE::DIR, path, -1, fs_itr->second.hash});
            }

            state_fs_entry_list.erase(fs_itr);
        }
        else
        {
            // If there was an entry that does not exist on other side, delete it from this node.
            if (fs_entry.is_file)
            {
                //if (statefs::delete_file(path) == -1)
                //    return -1;
            }
            else
            {
                //if (statefs::delete_dir(path) == -1)
                //    return -1;
            }
        }
    }

    // Queue the remaining fs entries (that this node does not have at all) to request.
    for (const auto &[path, fs_entry] : state_fs_entry_list)
    {
        if (fs_entry.is_file)
            pending_requests.push_front(backlog_item{BACKLOG_ITEM_TYPE::FILE, path, -1, fs_entry.hash});
        else
            pending_requests.push_back(backlog_item{BACKLOG_ITEM_TYPE::DIR, path, -1, fs_entry.hash});
    }

    return 0;
}

int handle_file_hashmap_response(const fbschema::p2pmsg::File_HashMap_Response *file_resp)
{
    std::string_view path_sv = fbschema::flatbuff_str_to_sv(file_resp->path());
    const std::string path_str(path_sv.data(), path_sv.size());

    std::vector<uint8_t> existing_block_hashmap;
    //if (statefs::get_block_hash_map(existing_block_hashmap, path_str, hpfs::h32_empty) == -1)
    //    return -1;

    const hpfs::h32 *existing_hashes = reinterpret_cast<const hpfs::h32 *>(existing_block_hashmap.data());
    auto existing_hash_count = existing_block_hashmap.size() / sizeof(hpfs::h32);

    const hpfs::h32 *resp_hashes = reinterpret_cast<const hpfs::h32 *>(file_resp->hash_map()->data());
    auto resp_hash_count = file_resp->hash_map()->size() / sizeof(hpfs::h32);

    auto insert_itr = pending_requests.begin();

    for (int block_id = 0; block_id < existing_hash_count; ++block_id)
    {
        if (block_id >= resp_hash_count)
            break;

        if (existing_hashes[block_id] != resp_hashes[block_id])
        {
            // Insert at front to give priority to block requests while preserving block order.
            pending_requests.insert(insert_itr, backlog_item{BACKLOG_ITEM_TYPE::BLOCK, path_str, block_id, resp_hashes[block_id]});
        }
    }

    if (existing_hash_count > resp_hash_count)
    {
        //if (statefs::truncate_file(path_str, file_resp->file_length()) == -1)
        //    return -1;
    }
    else if (existing_hash_count < resp_hash_count)
    {
        for (int block_id = existing_hash_count; block_id < resp_hash_count; ++block_id)
        {
            // Insert at front to give priority to block requests while preserving block order.
            pending_requests.insert(insert_itr, backlog_item{BACKLOG_ITEM_TYPE::BLOCK, path_str, block_id, resp_hashes[block_id]});
        }
    }

    return 0;
}

int handle_file_block_response(const fbschema::p2pmsg::Block_Response *block_msg)
{
    p2p::block_response block_resp = fbschema::p2pmsg::create_block_response_from_msg(*block_msg);

    //if (statefs::write_block(block_resp.path, block_resp.block_id, block_resp.data.data(), block_resp.data.size()) == -1)
    //    return -1;

    return 0;
}

} // namespace cons