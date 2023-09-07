#ifndef _HP_COMM_COMM_SESSION_
#define _HP_COMM_COMM_SESSION_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../corebill/tracker.hpp"
#include "hpws.hpp"
#include "comm_session_threshold.hpp"

namespace comm
{
    enum CHALLENGE_STATUS
    {
        NOT_ISSUED,
        CHALLENGE_ISSUED,
        CHALLENGE_VERIFIED
    };

    enum SESSION_STATE
    {
        NONE,       // Session is not yet initialized properly.
        ACTIVE,     // Session is active and functioning.
        MUST_CLOSE, // Session socket is in unusable state and must be closed.
        CLOSED      // Session is fully closed.
    };

    enum CLOSE_VIOLATION
    {
        VIOLATION_NONE = 0,
        VIOLATION_MSG_READ = 1,
        VIOLATION_READ_ERROR = 2,
        VIOLATION_THRESHOLD_EXCEEDED = 3,
        VIOLATION_INACTIVITY = 4
    };

    /**
     * Represents an active WebSocket connection
     */
    class comm_session
    {
    private:
        corebill::tracker &violation_tracker;
        const bool corebill_enabled; // Wether corebill enabled for the session.
        std::optional<hpws::client> hpws_client;
        std::vector<session_threshold> thresholds; // track down various communication thresholds

        std::thread reader_thread;                                      // The thread responsible for reading messages from the read fd.
        std::thread writer_thread;                                      // The thread responsible for writing messages to the write fd.
        moodycamel::ReaderWriterQueue<std::vector<char>> in_msg_queue1; // Holds high priority incoming messages waiting to be processed.
        moodycamel::ReaderWriterQueue<std::vector<char>> in_msg_queue2; // Holds low priority incoming messages waiting to be processed.
        moodycamel::ConcurrentQueue<std::string> out_msg_queue1;        // Holds high priority outgoing messages waiting to be processed.
        moodycamel::ConcurrentQueue<std::string> out_msg_queue2;        // Holds low priority outgoing messages waiting to be processed.

        void reader_loop();

    protected:
        virtual int handle_connect();
        virtual int get_message_priority(std::string_view msg);
        virtual int handle_message(std::string_view msg);
        virtual void handle_close();
        virtual void handle_on_verified();

    public:
        std::string uniqueid; // Verified session: Pubkey in hex format, Unverified session: IP address.
        std::string pubkey;   // Pubkey in binary format.
        const bool is_inbound;
        const bool is_ipv4;             // Whether the host is ipv4 or ipv6.
        const std::string host_address; // Connection host address of the remote party.
        std::string issued_challenge;
        SESSION_STATE state = SESSION_STATE::NONE;
        CHALLENGE_STATUS challenge_status = CHALLENGE_STATUS::NOT_ISSUED;
        uint64_t last_activity_timestamp; // Keep track of the last activity timestamp in milliseconds.

        comm_session(corebill::tracker &violation_tracker,
                     std::string_view host_address, hpws::client &&hpws_client, const bool is_ipv4, const bool is_inbound, const uint64_t (&metric_thresholds)[5], const bool corebill_enabled);
        int init();
        int process_next_inbound_message(const uint16_t priority);
        int send(const std::vector<uint8_t> &message, const uint16_t priority = 2);
        int send(std::string_view message, const uint16_t priority = 2);
        int process_outbound_message(std::string_view message);
        void process_outbound_msg_queue();
        void check_last_activity_rules();
        void mark_for_closure(const CLOSE_VIOLATION reason = CLOSE_VIOLATION::VIOLATION_NONE);
        void close();
        void mark_as_verified();
        virtual const std::string display_name() const;

        void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
        void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);
    };

} // namespace comm

#endif
