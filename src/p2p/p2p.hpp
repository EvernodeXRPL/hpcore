#ifndef _HP_P2P_
#define _HP_P2P_

#include "../pchheader.hpp"
#include "../usr/user_input.hpp"
#include "../util/h32.hpp"
#include "../util/sequence_hash.hpp"
#include "../conf.hpp"
#include "../hpfs/hpfs_mount.hpp"
#include "../msg/fbuf/p2pmsg_generated.h"
#include "peer_comm_server.hpp"
#include "peer_comm_session.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    constexpr uint16_t PROPOSAL_LIST_CAP = 64;        // Maximum proposal count.
    constexpr uint16_t NONUNL_PROPOSAL_LIST_CAP = 64; // Maximum nonunl proposal count.
    constexpr uint16_t HPFS_REQ_LIST_CAP = 64;        // Maximum state request count.
    constexpr uint16_t HPFS_RES_LIST_CAP = 64;        // Maximum state response count.
    constexpr uint16_t PEER_LIST_CAP = 64;            // Maximum peer count.
    constexpr uint16_t LOG_RECORD_REQ_LIST_CAP = 64;  // Maximum log record request count.
    constexpr uint16_t LOG_RECORD_RES_LIST_CAP = 64;  // Maximum log record response count.

    // Struct to represent information about a peer.
    // Initially available capacity is set to -1 and timestamp is set to 0.
    // Later it will be updated according to the capacity anouncement from the peers.
    struct peer_properties
    {
        conf::peer_ip_port ip_port;
        int16_t available_capacity = -1;
        uint64_t timestamp = 0;
        int64_t weight = 0;
    };


    struct proposal
    {
        std::string pubkey;

        uint64_t sent_timestamp = 0; // The timestamp of the sender when this proposal was sent.
        uint64_t recv_timestamp = 0; // The timestamp when we received the proposal. (used for network statistics)
        uint64_t time = 0;           // The descreet concensus time value that is voted on.
        uint8_t stage = 0;           // The round-stage that this proposal belongs to.
        uint32_t time_config = 0;    // Time config of the proposer.
        std::string nonce;           // Random nonce that is used to reduce lcl predictability.
        util::sequence_hash last_primary_shard_id;
        util::sequence_hash last_raw_shard_id;
        util::h32 state_hash; // Contract state hash.
        util::h32 patch_hash; // Patch file hash.
        std::set<std::string> users;
        std::set<std::string> input_ordered_hashes;
        std::string output_hash;
        std::string output_sig;
    };

    struct nonunl_proposal
    {
        std::unordered_map<std::string, std::list<usr::submitted_user_input>> user_inputs;
    };

    struct peer_challenge
    {
        std::string contract_id;
        uint32_t time_config = 0; // Contains unified value derived from (roundtime*100 + stage_slice)
        bool is_full_history = false;
        std::string challenge;
    };

    struct peer_challenge_response
    {
        std::string challenge;
        std::string signature;
        std::string pubkey;
    };

    struct peer_capacity_announcement
    {
        int16_t available_capacity = 0;
        uint64_t timestamp = 0;
    };

    struct peer_requirement_announcement
    {
        bool need_consensus_msg_forwarding = false;
    };

    // Represents an NPL message sent by a peer.
    struct npl_message
    {
        std::string pubkey;        // Peer binary pubkey.
        util::sequence_hash lcl_id; // lcl of the peer.
        std::string data;
    };

    // Represents hpfs log sync request.
    struct hpfs_log_request
    {
        uint64_t target_seq_no;
        util::sequence_hash min_record_id;
    };

    // Represents hpfs log sync response.
    struct hpfs_log_response
    {
        util::sequence_hash min_record_id;
        std::vector<uint8_t> log_record_bytes;
    };

    enum HPFS_FS_ENTRY_RESPONSE_TYPE
    {
        MATCHED = 0,      // The entry matches between requester and responder. No sync needed.
        MISMATCHED = 1,   // The entry does not match (either hash mismatch or new entry). Requester must request for this entry.
        RESPONDED = 2,    // The entry does not match and the repsonder has dispatched the sync response.
        NOT_AVAILABLE = 3 // The entry does not exist on responder side. Requester must delete this on his side.
    };

    // Represents hpfs file system entry.
    struct hpfs_fs_hash_entry
    {
        std::string name;     // Name of the file/dir.
        bool is_file = false; // Whether this is a file or dir.
        util::h32 hash;       // Hash of the file or dir.

        // Only relevant for hpfs responses. Indicates about the availabilty and status of this
        // fs entry as reported by the responder.
        HPFS_FS_ENTRY_RESPONSE_TYPE response_type = HPFS_FS_ENTRY_RESPONSE_TYPE::MATCHED;
    };

    // Represents a file block data resposne.
    struct block_response
    {
        std::string path;      // Path of the file.
        uint32_t block_id = 0; // Id of the block where the data belongs to.
        std::string_view data; // The block data.
        util::h32 hash;        // Hash of the bloc data.
    };

    // Represents a hpfs request sent to a peer.
    struct hpfs_request
    {
        uint32_t mount_id = 0;                          // Relavent file system id.
        std::string parent_path;                        // The requested file or dir path.
        bool is_file = false;                           // Whether the path is a file or dir.
        int32_t block_id = 0;                           // Block id of the file if we are requesting for file block. Otherwise -1.
        util::h32 expected_hash;                        // The expected hash of the requested result.
        std::vector<hpfs_fs_hash_entry> fs_entry_hints; // Included fs entry entry hints for the responder.
        std::vector<util::h32> file_hashmap_hints;      // Included file hash map hints for the responder.
    };

    struct peer_message_info
    {
        const msg::fbuf::p2pmsg::P2PMsg *p2p_msg = NULL;
        const enum msg::fbuf::p2pmsg::P2PMsgContent type = msg::fbuf::p2pmsg::P2PMsgContent_NONE;
        const uint64_t originated_on = 0;
    };

    struct message_collection
    {
        std::list<proposal> proposals;
        std::mutex proposals_mutex; // Mutex for proposals access race conditions.

        std::list<nonunl_proposal> nonunl_proposals;
        std::mutex nonunl_proposals_mutex; // Mutex for non-unl proposals access race conditions.

        // List of pairs indicating the session pubkey hex and the contract fs hpfs requests.
        std::list<std::pair<std::string, p2p::hpfs_request>> contract_hpfs_requests;
        std::mutex contract_hpfs_requests_mutex; // Mutex for contract fs hpfs requests access race conditions.

        // List of pairs indicating the session pubkey hex and the ledger fs hpfs requests.
        std::list<std::pair<std::string, p2p::hpfs_request>> ledger_hpfs_requests;
        std::mutex ledger_hpfs_requests_mutex; // Mutex for ledger fs hpfs requests access race conditions.

        // List of pairs indicating the session pubkey hex and the contract fs hpfs responses.
        std::list<std::pair<std::string, std::string>> contract_hpfs_responses;
        std::mutex contract_hpfs_responses_mutex; // Mutex for contract fs hpfs responses access race conditions.

        // List of pairs indicating the session pubkey hex and the ledger fs hpfs responses.
        std::list<std::pair<std::string, std::string>> ledger_hpfs_responses;
        std::mutex ledger_hpfs_responses_mutex; // Mutex for ledger fs hpfs responses access race conditions.

        // Lists holding hpfs log requests and responses collected from incoming p2p messages.
        std::list<std::pair<std::string, p2p::hpfs_log_request>> hpfs_log_requests;
        std::mutex hpfs_log_request_mutex; // Mutex for hpfs log request access race conditions.

        std::list<std::pair<std::string, p2p::hpfs_log_response>> hpfs_log_responses;
        std::mutex hpfs_log_response_mutex; // Mutex for hpfs log responses access race conditions.
    };

    struct connected_context
    {
        // Holds all the messages until they are processed by consensus.
        message_collection collected_msgs;

        // Set of currently connected peer connections mapped by the binary pubkey of socket session.
        std::unordered_map<std::string, peer_comm_session *> peer_connections;

        std::mutex peer_connections_mutex; // Mutex for peer connections access race conditions.

        std::optional<peer_comm_server> server;
    };

    extern connected_context ctx;

    int init();

    void deinit();

    int start_peer_connections();

    int resolve_peer_challenge(peer_comm_session &session, const peer_challenge_response &challenge_resp);

    void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self, const bool is_msg_forwarding = false, const bool unl_only = false, const uint16_t priority = 2);

    void broadcast_message(std::string_view message, const bool send_to_self, const bool is_msg_forwarding = false, const bool unl_only = false, const peer_comm_session *skipping_session = NULL, const uint16_t priority = 2);

    void send_message_to_self(const flatbuffers::FlatBufferBuilder &fbuf);

    void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf, std::string &target_pubkey, const bool full_history_only = false);

    void handle_proposal_message(const p2p::proposal &p);

    void handle_nonunl_proposal_message(const p2p::nonunl_proposal &nup);

    void handle_npl_message(const p2p::npl_message &npl);

    bool validate_for_peer_msg_forwarding(const peer_comm_session &session, const enum msg::fbuf::p2pmsg::P2PMsgContent msg_type, const uint64_t originated_on);

    void send_peer_requirement_announcement(const bool need_consensus_msg_forwarding, peer_comm_session *session = NULL);

    void send_available_capacity_announcement(const int16_t &available_capacity);

    void send_known_peer_list(peer_comm_session *session);

    void send_peer_list_request();

    void update_known_peer_available_capacity(const conf::peer_ip_port &ip_port, const int16_t available_capacity, const uint64_t &timestamp);

    void merge_peer_list(const std::vector<peer_properties> &peers);

    void sort_known_remotes();

    int16_t get_available_capacity();

    void update_unl_connections();

} // namespace p2p

#endif