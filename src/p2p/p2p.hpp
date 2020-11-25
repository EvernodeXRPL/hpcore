#ifndef _HP_P2P_
#define _HP_P2P_

#include "../pchheader.hpp"
#include "../usr/user_input.hpp"
#include "../hpfs/h32.hpp"
#include "../conf.hpp"
#include "../msg/fbuf/p2pmsg_container_generated.h"
#include "peer_comm_server.hpp"
#include "peer_comm_session.hpp"
#include "peer_session_handler.hpp"

namespace p2p
{
    constexpr uint16_t PROPOSAL_LIST_CAP = 64;        // Maximum proposal count.
    constexpr uint16_t NONUNL_PROPOSAL_LIST_CAP = 64; // Maximum nonunl proposal count.
    constexpr uint16_t STATE_REQ_LIST_CAP = 64;       // Maximum state request count.
    constexpr uint16_t STATE_RES_LIST_CAP = 64;       // Maximum state response count.
    constexpr uint16_t PEER_LIST_CAP = 64;            // Maximum peer count.

    struct proposal
    {
        std::string pubkey;

        uint64_t sent_timestamp = 0; // The timestamp of the sender when this proposal was sent.
        uint64_t time = 0;           // The time value that is voted on.
        uint8_t stage = 0;
        std::string nonce; // Random nonce that is used to reduce lcl predictability.
        std::string lcl;
        hpfs::h32 state;
        std::set<std::string> users;
        std::set<std::string> hash_inputs;
        std::set<std::string> hash_outputs;
    };

    struct nonunl_proposal
    {
        std::unordered_map<std::string, std::list<usr::user_input>> user_inputs;
    };

    struct history_request
    {
        std::string requester_lcl;
        std::string minimum_lcl;
        std::string required_lcl;
    };

    struct history_ledger_block
    {
        std::string lcl;
        std::vector<uint8_t> block_buffer;
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
        std::string requester_lcl;
        std::map<uint64_t, const history_ledger_block> hist_ledger_blocks;
        LEDGER_RESPONSE_ERROR error = LEDGER_RESPONSE_ERROR::NONE;
    };

    // Represents an NPL message sent by a peer.
    struct npl_message
    {
        std::string pubkey; // Peer binary pubkey.
        std::string lcl;    // LCL of the peer.
        std::string data;
    };

    // Represents a state request sent to a peer.
    struct state_request
    {
        std::string parent_path; // The requested file or dir path.
        bool is_file = false;    // Whether the path is a file or dir.
        int32_t block_id = 0;    // Block id of the file if we are requesting for file block. Otherwise -1.
        hpfs::h32 expected_hash; // The expected hash of the requested result.
    };

    // Represents state file system entry.
    struct state_fs_hash_entry
    {
        std::string name;     // Name of the file/dir.
        bool is_file = false; // Whether this is a file or dir.
        hpfs::h32 hash;       // Hash of the file or dir.
    };

    // Represents a file block data resposne.
    struct block_response
    {
        std::string path;      // Path of the file.
        uint32_t block_id = 0; // Id of the block where the data belongs to.
        std::string_view data; // The block data.
        hpfs::h32 hash;        // Hash of the bloc data.
    };

    struct message_collection
    {
        std::list<proposal> proposals;
        std::mutex proposals_mutex; // Mutex for proposals access race conditions.

        std::list<nonunl_proposal> nonunl_proposals;
        std::mutex nonunl_proposals_mutex; // Mutex for non-unl proposals access race conditions.

        // List of pairs indicating the session pubkey hex and the state requests.
        std::list<std::pair<std::string, std::string>> state_requests;
        std::mutex state_requests_mutex; // Mutex for state requests access race conditions.

        // List of pairs indicating the session pubkey hex and the state responses.
        std::list<std::pair<std::string, std::string>> state_responses;
        std::mutex state_responses_mutex; // Mutex for state responses access race conditions.
    };

    struct connected_context
    {
        // Holds all the messages until they are processed by consensus.
        message_collection collected_msgs;

        // Set of currently connected peer connections mapped by the uniqueid of socket session.
        std::unordered_map<std::string, peer_comm_session *> peer_connections;

        std::mutex peer_connections_mutex; // Mutex for peer connections access race conditions.

        std::optional<peer_comm_server> server;
    };

    extern connected_context ctx;

    int init();

    void deinit();

    int start_peer_connections();

    int resolve_peer_challenge(peer_comm_session &session, const peer_challenge_response &challenge_resp);

    void broadcast_message(const flatbuffers::FlatBufferBuilder &fbuf, const bool send_to_self, const bool is_msg_forwarding = false);

    void broadcast_message(std::string_view message, const bool send_to_self, const bool is_msg_forwarding = false, const peer_comm_session *skipping_session = NULL);

    void send_message_to_self(const flatbuffers::FlatBufferBuilder &fbuf);

    void send_message_to_random_peer(const flatbuffers::FlatBufferBuilder &fbuf, std::string &target_pubkey);

    bool validate_for_peer_msg_forwarding(const peer_comm_session &session, const msg::fbuf::p2pmsg::Container *container, const msg::fbuf::p2pmsg::Message &content_message_type);

    void send_peer_requirement_announcement(const bool need_consensus_msg_forwarding, peer_comm_session *session = NULL);

    void send_available_capacity_announcement(const int16_t &available_capacity);

    void send_known_peer_list(peer_comm_session *session);

    void send_peer_list_request();

    void update_known_peer_available_capacity(const conf::ip_port_prop &ip_port, const int16_t available_capacity, const uint64_t &timestamp);

    void merge_peer_list(const std::vector<conf::peer_properties> &peers);

    int32_t get_peer_weight(const conf::peer_properties &peer);

    void sort_known_remotes();

    int16_t get_available_capacity();
} // namespace p2p

#endif