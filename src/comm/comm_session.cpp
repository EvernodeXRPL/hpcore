#include "../pchheader.hpp"
#include "../hplog.hpp"
#include "../util/util.hpp"
#include "../conf.hpp"
#include "../bill/corebill.h"
#include "../hpws/hpws.hpp"
#include "comm_session.hpp"

namespace comm
{
    constexpr uint32_t INTERVALMS = 60000;
    constexpr uint16_t UNVERIFIED_INACTIVE_TIMEOUT = 5; // Time threshold for unverified inactive connections in seconds.

    comm_session::comm_session(
        std::string_view host_address, hpws::client &&hpws_client, const bool is_inbound, const uint64_t (&metric_thresholds)[5])
        : uniqueid(host_address),
          host_address(host_address),
          hpws_client(std::move(hpws_client)),
          is_inbound(is_inbound),
          in_msg_queue(32)
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
                std::vector<char> msg(data.size());
                memcpy(msg.data(), data.data(), data.size());
                in_msg_queue.enqueue(std::move(msg));

                // Signal the hpws client that we are ready for next message.
                std::optional<hpws::error> error = hpws_client->ack(data);
                if (error.has_value())
                {
                    LOG_DEBUG << "hpws client ack failed:" << error.value().first << " " << error.value().second;
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
     * @return 0 if no messages in queue. 1 if message was processed. -1 means session must be closed.
     */
    int comm_session::process_next_inbound_message()
    {
        if (state != SESSION_STATE::ACTIVE)
            return 0;

        std::vector<char> msg;
        if (in_msg_queue.try_dequeue(msg))
        {
            std::string_view sv(msg.data(), msg.size());
            const int sess_handler_result = handle_message(sv);

            // If session handler returns -1 then that means the session must be closed.
            // Otherwise it's considered message processing is successful.
            return sess_handler_result == -1 ? -1 : 1;
        }

        return 0;
    }

    int comm_session::send(const std::vector<uint8_t> &message)
    {
        std::string_view sv(reinterpret_cast<const char *>(message.data()), message.size());
        send(sv);
        return 0;
    }

    /**
     * Adds the given message to the outbound message queue.
     * @param message Message to be added to the outbound queue.
     * @return 0 on successful addition and -1 if the session is already closed.
    */
    int comm_session::send(std::string_view message)
    {
        if (state == SESSION_STATE::CLOSED)
            return -1;

        // Updating last activity timestamp since this session is sending a message.
        last_activity_timestamp = util::get_epoch_milliseconds();

        // Passing the ownership of message to the queue.
        out_msg_queue.enqueue(std::string(message));
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
            LOG_DEBUG << "hpws client write failed:" << error.value().first << " " << error.value().second;
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
            std::string msg_to_send;

            // If the queue is not empty, the first element will be processed,
            // else wait 10ms until queue gets populated.
            if (out_msg_queue.try_dequeue(msg_to_send))
            {
                process_outbound_message(msg_to_send);
            }
            else
            {
                util::sleep(10);
            }
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
    void comm_session::close(const bool invoke_handler)
    {
        if (state == SESSION_STATE::CLOSED)
            return;

        if (invoke_handler)
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
    const std::string comm_session::display_name()
    {
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
        else
        {
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
    }

    /**
     * Check whether the connection expires according to last activity time rules and then mark for closure.
    */
    void comm_session::check_last_activity_rules()
    {
        const uint16_t timeout_seconds = (challenge_status == CHALLENGE_STATUS::CHALLENGE_VERIFIED ? thresholds[SESSION_THRESHOLDS::IDLE_CONNECTION_TIMEOUT].threshold_limit : UNVERIFIED_INACTIVE_TIMEOUT);

        // Timeout zero means unlimited.
        if (timeout_seconds == 0)
            return;

        if (util::get_epoch_milliseconds() - last_activity_timestamp >= (timeout_seconds * 1000))
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