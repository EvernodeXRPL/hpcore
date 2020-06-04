#ifndef _HP_P2P_
#define _HP_P2P_

#include "../pchheader.hpp"
#include "../comm/comm_server.hpp"
#include "../comm/comm_client.hpp"
#include "../comm/comm_session.hpp"
#include "../usr/user_input.hpp"
#include "peer_session_handler.hpp"
#include "../hpfs/h32.hpp"
#include "../conf.hpp"

namespace p2p
{

struct proposal
{
    std::string pubkey;
    uint64_t timestamp;
    uint64_t time;
    uint8_t stage;
    std::string lcl;
    hpfs::h32 curr_state_hash;
    std::set<std::string> users;
    std::set<std::string> hash_inputs;
    std::set<std::string> hash_outputs;
};

struct nonunl_proposal
{
    std::unordered_map<std::string, const std::list<usr::user_submitted_message>> user_messages;
};

struct history_request
{
    std::string minimum_lcl;
    std::string required_lcl;
};

struct history_ledger
{
    std::string state;
    std::string lcl;
    std::vector<uint8_t> raw_ledger;
};

struct peer_challenge_response
{
    std::string challenge;
    std::string signature;
    std::string pubkey;
};

enum LEDGER_RESPONSE_ERROR
{
    NONE = 0,
    INVALID_MIN_LEDGER = 1,
    REQ_LEDGER_NOT_FOUND = 2
};

struct history_response
{
    std::map<uint64_t, const history_ledger> hist_ledgers;
    LEDGER_RESPONSE_ERROR error;
};

struct npl_message
{
    std::string data;
};

// Represents a state request sent to a peer.
struct state_request
{
    std::string parent_path;   // The requested file or dir path.
    bool is_file;              // Whether the path is a file or dir.
    int32_t block_id;          // Block id of the file if we are requesting for file block. Otherwise -1.
    hpfs::h32 expected_hash; // The expected hash of the requested result.
};

// Represents state file system entry.
struct state_fs_hash_entry
{
    bool is_file;     // Whether this is a file or dir.
    hpfs::h32 hash; // Hash of the file or dir.
};

// Represents a file block data resposne.
struct block_response
{
    std::string path;      // Path of the file.
    uint32_t block_id;     // Id of the block where the data belongs to.
    std::string_view data; // The block data.
    hpfs::h32 hash;      // Hash of the bloc data.
};

struct message_collection
{
    std::list<proposal> proposals;
    std::mutex proposals_mutex; // Mutex for proposals access race conditions.

    std::list<nonunl_proposal> nonunl_proposals;
    std::mutex nonunl_proposals_mutex; // Mutex for non-unl proposals access race conditions.

    // NPL messages are stored as string list because we are feeding the npl messages as it is (byte array) to the contract.
    std::list<std::string> npl_messages;
    std::mutex npl_messages_mutex; // Mutex for npl_messages access race conditions.

    std::list<std::string> state_response;
    std::mutex state_response_mutex; // Mutex for state response access race conditions.
};

struct connected_context
{
    // Holds all the messages until they are processed by consensus.
    message_collection collected_msgs;

    // Set of currently connected peer connections mapped by the uniqueid of socket session.
    std::unordered_map<std::string, comm::comm_session *> peer_connections;

    std::mutex peer_connections_mutex; // Mutex for peer connections access race conditions.

    comm::comm_server listener;
};

extern connected_context ctx;

int init();

void deinit();

int start_peer_connections();

int resolve_peer_challenge(comm::comm_session &session, const peer_challenge_response &challenge_resp);

void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self);

void send_message_to_self(const flatbuffers::FlatBufferBuilder &fbuf);

void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf);

} // namespace p2p

#endif