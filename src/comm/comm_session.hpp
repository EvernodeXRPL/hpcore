#ifndef _HP_COMM_COMM_SESSION_
#define _HP_COMM_COMM_SESSION_

#include "../pchheader.hpp"
#include "../conf.hpp"
#include "../hpws/hpws.hpp"
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

    /** 
     * Represents an active WebSocket connection
     */
    class comm_session
    {
    private:
        std::optional<hpws::client> hpws_client;
        std::vector<session_threshold> thresholds; // track down various communication thresholds

        std::thread reader_thread;                                     // The thread responsible for reading messages from the read fd.
        std::thread writer_thread;                                     // The thread responsible for writing messages to the write fd.
        moodycamel::ReaderWriterQueue<std::vector<char>> in_msg_queue; // Holds incoming messages waiting to be processed.
        moodycamel::ConcurrentQueue<std::string> out_msg_queue;        // Holds outgoing messages waiting to be processed.

        void reader_loop();

    protected:
        virtual void handle_connect();
        virtual int handle_message(std::string_view msg);
        virtual void handle_close();

    public:
        std::string uniqueid;
        const bool is_inbound;
        const std::string host_address; // Connection host address of the remote party.
        std::string issued_challenge;
        SESSION_STATE state = SESSION_STATE::NONE;
        CHALLENGE_STATUS challenge_status = CHALLENGE_STATUS::NOT_ISSUED;

        comm_session(
            std::string_view host_address, hpws::client &&hpws_client, const bool is_inbound, const uint64_t (&metric_thresholds)[4]);
        void init();
        int process_next_inbound_message();
        int send(const std::vector<uint8_t> &message);
        int send(std::string_view message);
        int process_outbound_message(std::string_view message);
        void process_outbound_msg_queue();
        void mark_for_closure();
        void close(const bool invoke_handler = true);
        virtual const std::string display_name();

        void set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms);
        void increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount);
    };

} // namespace comm

#endif
