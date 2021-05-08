#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../conf.hpp"
#include "../bill/corebill.h"
#include "hpws.hpp"
#include "comm_session.hpp"

namespace comm
{
    constexpr uint32_t INTERVALMS = 60000;
    constexpr uint32_t UNVERIFIED_INACTIVE_TIMEOUT = 5000; // Time threshold ms for unverified inactive connections.
    constexpr uint16_t MAX_IN_MSG_QUEUE_SIZE = 64;         // Maximum in message queue size, The size passed is rounded to next number in binary sequence 1(1),11(3),111(7),1111(15),11111(31)....

    comm_session::comm_session(
        std::string_view host_address, hpws::client &&hpws_client, const bool is_inbound, const uint64_t (&metric_thresholds)[5])
        : uniqueid(host_address),
          host_address(host_address),
          hpws_client(std::move(hpws_client)),
          is_inbound(is_inbound),
          in_msg_queue1(MAX_IN_MSG_QUEUE_SIZE),
          in_msg_queue2(MAX_IN_MSG_QUEUE_SIZE)
    {
        // Create new session_thresholds and insert it to thresholds vector.
        // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
        // since enum's value is used as index in the vector to update vector values.
        thresholds.reserve(5);
        for (size_t i = 0; i < 5; i++)
            thresholds.push_back(session_threshold(metric_thresholds[i], INTERVALMS));
    }

    /**
     * Init() should be called to activate the session.
     * Because we are starting threads here, after init() is called, the session object must not be "std::moved".
     * @return returns 0 on successful init, otherwise -1;
     */
    int comm_session::init()
    {
        if (state == SESSION_STATE::NONE)
        {
            if (handle_connect() == -1)
            {
                mark_for_closure();
                return -1;
            }

            reader_thread = std::thread(&comm_session::reader_loop, this);
            writer_thread = std::thread(&comm_session::process_outbound_msg_queue, this);
            state = SESSION_STATE::ACTIVE;
            last_activity_timestamp = util::get_epoch_milliseconds();
        }

        return 0;
    }

    void comm_session::reader_loop()
    {
        util::mask_signal();

        while (state != SESSION_STATE::CLOSED && hpws_client)
        {
            bool should_disconnect = false;

            std::variant<std::string_view, hpws::error> read_result = hpws_client->read();
            if (std::holds_alternative<hpws::error>(read_result))
            {
                should_disconnect = true;
                const hpws::error error = std::get<hpws::error>(read_result);
                if (error.first != 1) // 1 indicates channel has closed.
                    LOG_DEBUG << "hpws client read failed:" << error.first << " " << error.second;
            }
            else
            {
                // Update last activity timestamp since this session received a message.
                last_activity_timestamp = util::get_epoch_milliseconds();

                // Enqueue the message for processing.
                std::string_view data = std::get<std::string_view>(read_result);

                // Detect message priority before adding to the message queue.
                const int priority = get_message_priority(data);
                if (priority == 0) // priority 0 means a bad message.
                {
                    increment_metric(comm::SESSION_THRESHOLDS::MAX_BADMSGS_PER_MINUTE, 1);
                }
                else if (priority == 1 || priority == 2)
                {
                    std::vector<char> msg(data.size());
                    memcpy(msg.data(), data.data(), data.size());

                    if (priority == 1)
                        in_msg_queue1.try_enqueue(std::move(msg));
                    else if (priority == 2)
                        in_msg_queue2.try_enqueue(std::move(msg));
                }

                // Signal the hpws client that we are ready for next message.
                std::optional<hpws::error> error = hpws_client->ack(data);
                if (error.has_value())
                {
                    LOG_DEBUG << "hpws client ack failed:" << error->first << " " << error->second;
                    should_disconnect = true;
                }
            }

            if (should_disconnect)
            {
                // Here we mark the session as needing to close.
                // The session will be properly "closed" and cleaned up by the global comm_server thread.
                mark_for_closure();
                break;
            }
        }
    }

    /**
     * Processes the next queued message (if any).
     * @param priority Which priority queue to process.
     * @return 0 if no messages in queue. 1 if a message were processed. -1 means session must be closed.
     */
    int comm_session::process_next_inbound_message(const uint16_t priority)
    {
        if (state != SESSION_STATE::ACTIVE)
            return 0;

        int res = 0;

        moodycamel::ReaderWriterQueue<std::vector<char>> &queue = (priority == 1 ? in_msg_queue1 : in_msg_queue2);

        // Process queue top.
        std::vector<char> msg;
        if (queue.try_dequeue(msg))
        {
            std::string_view sv(msg.data(), msg.size());

            // If session handler returns -1 then that means the session must be closed.
            // Otherwise it's considered message processing is successful.
            if (handle_message(sv) == -1)
                return -1;
            else
                res = 1;
        }

        return res;
    }

    /**
     * Adds the given message to the outbound message queue.
     * @param message Message to be added to the outbound queue.
     * @param priority If 1 adds to high priority queue. Else adds to low priority queue.
     * @return 0 on successful addition and -1 if the session is already closed.
    */
    int comm_session::send(const std::vector<uint8_t> &message, const uint16_t priority)
    {
        std::string_view sv(reinterpret_cast<const char *>(message.data()), message.size());
        return send(sv);
    }

    /**
     * Adds the given message to the outbound message queue.
     * @param message Message to be added to the outbound queue.
     * @param priority If 1 adds to high priority queue. Else adds to low priority queue.
     * @return 0 on successful addition and -1 if the session is already closed.
    */
    int comm_session::send(std::string_view message, const uint16_t priority)
    {
        if (state == SESSION_STATE::CLOSED)
            return -1;

        // Updating last activity timestamp since this session is sending a message.
        last_activity_timestamp = util::get_epoch_milliseconds();

        // Passing the ownership of message to the queue based on specified priority.
        if (priority == 1)
            out_msg_queue1.enqueue(std::string(message));
        else
            out_msg_queue2.enqueue(std::string(message));

        return 0;
    }

    /**
     * This function constructs and sends the message to the target from the given message.
     * @param message Message to be sent via the pipe.
     * @return 0 on successful message sent and -1 on error.
    */
    int comm_session::process_outbound_message(std::string_view message)
    {
        if (state == SESSION_STATE::CLOSED || !hpws_client)
            return -1;

        std::optional<hpws::error> error = hpws_client->write(message);
        if (error.has_value())
        {
            LOG_DEBUG << "hpws client write failed:" << error->first << " " << error->second;
            return -1;
        }
        return 0;
    }

    /**
     * Process message sending in the queue in the outbound_queue_thread.
    */
    void comm_session::process_outbound_msg_queue()
    {
        // Appling a signal mask to prevent receiving control signals from linux kernel.
        util::mask_signal();

        // Keep checking until the session is terminated.
        while (state != SESSION_STATE::CLOSED)
        {
            bool messages_sent = false;
            std::string msg_to_send;

            // Send all messages in high priority queue.
            while (out_msg_queue1.try_dequeue(msg_to_send))
            {
                process_outbound_message(msg_to_send);
                msg_to_send.clear();
                messages_sent = true;
            }

            // Send top message in low priority queue.
            if (out_msg_queue2.try_dequeue(msg_to_send))
            {
                process_outbound_message(msg_to_send);
                messages_sent = true;
            }

            // Wait for small delay if there were no outbound messages.
            if (!messages_sent)
                util::sleep(10);
        }
    }

    /**
     * Mark the session as needing to close. The session will be properly "closed"
     * and cleaned up by the global comm_server thread.
     */
    void comm_session::mark_for_closure()
    {
        if (state == SESSION_STATE::CLOSED)
            return;

        state = SESSION_STATE::MUST_CLOSE;
    }

    /**
     * Close the connection and wrap up any session processing threads.
     * This will be only called by the global comm_server thread.
     */
    void comm_session::close()
    {
        if (state == SESSION_STATE::CLOSED)
            return;

        // Invoking the handler of the derived class for cleanups.
        handle_close();

        state = SESSION_STATE::CLOSED;

        // Destruct the hpws client instance so it will close the sockets and related processes.
        hpws_client.reset();

        // Wait untill reader/writer threads gracefully stop.
        if (writer_thread.joinable())
            writer_thread.join();

        if (reader_thread.joinable())
            reader_thread.join();

        LOG_DEBUG << "Session closed: " << display_name();
    }

    /**
     * Returns printable name for the session based on uniqueid (used for logging).
     */
    const std::string comm_session::display_name() const
    {
        if (challenge_status == comm::CHALLENGE_STATUS::CHALLENGE_VERIFIED)
        {
            // Sessions use pubkey hex as unique id (skipping first 2 bytes key type prefix).
            return uniqueid.substr(2, 10) + (is_inbound ? ":in" : ":out");
        }

        return uniqueid + (is_inbound ? ":in" : ":out");
    }

    /**
     * Set thresholds to the socket session
    */
    void comm_session::set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms)
    {
        session_threshold &t = thresholds[threshold_type];
        t.counter_value = 0;
        t.intervalms = intervalms;
        t.threshold_limit = threshold_limit;
    }

    /*
    * Increment the provided thresholds counter value with the provided amount and validate it against the
    * configured threshold limit.
    */
    void comm_session::increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount)
    {
        session_threshold &t = thresholds[threshold_type];

        // Ignore the counter if limit is set as 0.
        if (t.threshold_limit == 0)
            return;

        const uint64_t time_now = util::get_epoch_milliseconds();

        t.counter_value += amount;
        if (t.timestamp == 0)
        {
            // Reset counter timestamp.
            t.timestamp = time_now;
        }

        // Check whether we have exceeded the threshold within the monitering interval.
        const uint64_t elapsed_time = time_now - t.timestamp;
        if (elapsed_time <= t.intervalms && t.counter_value > t.threshold_limit)
        {
            mark_for_closure();

            t.timestamp = 0;
            t.counter_value = 0;

            LOG_INFO << "Session " << display_name() << " threshold exceeded. (type:" << threshold_type << " limit:" << t.threshold_limit << ")";
            corebill::report_violation(host_address);
        }
        else if (elapsed_time > t.intervalms)
        {
            t.timestamp = time_now;
            t.counter_value = amount;
        }
    }

    /**
     * Check whether the connection expires according to last activity time rules and then mark for closure.
    */
    void comm_session::check_last_activity_rules()
    {
        const uint32_t timeout = (challenge_status == CHALLENGE_STATUS::CHALLENGE_VERIFIED ? thresholds[SESSION_THRESHOLDS::IDLE_CONNECTION_TIMEOUT].threshold_limit : UNVERIFIED_INACTIVE_TIMEOUT);

        // Timeout zero means unlimited.
        if (timeout == 0)
            return;

        if (util::get_epoch_milliseconds() - last_activity_timestamp >= timeout)
        {
            LOG_DEBUG << "Closing " << display_name() << " connection due to inactivity.";
            mark_for_closure();
        }
    }

    /**
     * Mark the connection as a verified connection.
    */
    void comm_session::mark_as_verified()
    {
        challenge_status = CHALLENGE_STATUS::CHALLENGE_VERIFIED;
        handle_on_verified();
    }

    int comm_session::handle_connect()
    {
        return 0;
    }

    int comm_session::get_message_priority(std::string_view msg)
    {
        return 2; // Default is low priority.
    }

    int comm_session::handle_message(std::string_view msg)
    {
        return 0;
    }

    void comm_session::handle_close()
    {
    }

    void comm_session::handle_on_verified()
    {
    }

} // namespace comm