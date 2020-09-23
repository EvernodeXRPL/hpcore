#include "../pchheader.hpp"
#include "../usr/user_session_handler.hpp"
#include "../p2p/peer_session_handler.hpp"
#include "comm_session.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../bill/corebill.h"

namespace comm
{
    constexpr uint32_t INTERVALMS = 60000;
    constexpr uint8_t SIZE_HEADER_LEN = 8;
    constexpr short READER_POLL_EVENTS = POLLIN | POLLRDHUP;

    // Global instances of user and peer session handlers.
    usr::user_session_handler user_sess_handler;
    p2p::peer_session_handler peer_sess_handler;

    comm_session::comm_session(
        std::string_view ip, const int read_fd, const int write_fd, const SESSION_TYPE session_type,
        const bool is_binary, const bool is_inbound, const uint64_t (&metric_thresholds)[4], const uint64_t max_msg_size)

        : read_fd(read_fd),
          write_fd(write_fd),
          session_type(session_type),
          uniqueid(std::to_string(read_fd).append(":").append(ip)),
          is_binary(is_binary),
          is_inbound(is_inbound),
          max_msg_size(max_msg_size),
          in_msg_queue(32)
    {
        // Create new session_thresholds and insert it to thresholds vector.
        // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
        // since enum's value is used as index in the vector to update vector values.
        thresholds.reserve(4);
        for (size_t i = 0; i < 4; i++)
            thresholds.push_back(session_threshold(metric_thresholds[i], INTERVALMS));
    }

    /**
     * Starts the outbound queue processing thread.
    */
    void comm_session::start_messaging_threads()
    {
        reader_thread = std::thread(&comm_session::reader_loop, this);
        writer_thread = std::thread(&comm_session::process_outbound_msg_queue, this);
    }

    void comm_session::reader_loop()
    {
        util::mask_signal();

        while (state != SESSION_STATE::CLOSED)
        {
            pollfd pollfds[1] = {{read_fd, READER_POLL_EVENTS}};

            if (poll(pollfds, 1, 20) == -1)
            {
                LOG_ERROR << errno << ": Session reader poll failed.";
                break;
            }

            const short result = pollfds[0].revents;
            bool should_disconnect = false;

            if (result & POLLIN)
            {
                // read_result -1 means error and we should disconnect the client.
                // read_result 0 means no bytes were read.
                // read_result 1 means some bytes were read.
                // read_result 2 means full message were read and processed successfully.
                const int read_result = attempt_read();

                if (read_result == -1)
                    should_disconnect = true;
            }

            if (!should_disconnect && (result & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)))
                should_disconnect = true;

            if (should_disconnect)
            {
                // Here we mark the session as needing to close.
                // The session will be properly "closed" and cleaned up by the global comm_server thread.
                mark_for_closure();
                break;
            }
        }
    }

    int comm_session::on_connect()
    {
        state = SESSION_STATE::ACTIVE;

        if (session_type == SESSION_TYPE::USER)
            return user_sess_handler.on_connect(*this);
        else
            return peer_sess_handler.on_connect(*this);
    }

    /**
 * Attempts to read message data from the given socket fd and passes the message on to the session.
 * @return  -1 on error and client must be disconnected. 0 if no message data bytes were read. 1 if some
 *          bytes were read but a full message is not yet formed. 2 if a fully formed message has been
 *          read into the read buffer.
 */
    int comm_session::attempt_read()
    {
        size_t available_bytes = 0;
        if (ioctl(read_fd, FIONREAD, &available_bytes) == -1 ||
            (max_msg_size > 0 &&
             available_bytes > (max_msg_size + (is_binary ? SIZE_HEADER_LEN : 0))))
            return -1;

        int res = 0;

        // Try to read a complete message using available bytes.
        if (available_bytes > 0)
        {
            increment_metric(SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, available_bytes);

            if (is_binary)
            {
                res = attempt_binary_msg_construction(available_bytes);
            }
            else
            {
                read_buffer.resize(available_bytes);
                res = read(read_fd, read_buffer.data(), available_bytes) < available_bytes ? -1 : 2;
            }

            if (res == 2) // Full message has been read into read buffer.
            {
                std::vector<char> msg;
                msg.swap(read_buffer);
                read_buffer_filled_size = 0;

                in_msg_queue.enqueue(std::move(msg));
            }
        }

        return res;
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
            const int sess_handler_result = (session_type == SESSION_TYPE::USER)
                                                ? user_sess_handler.on_message(*this, sv)
                                                : peer_sess_handler.on_message(*this, sv);

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
    }

    /**
     * Adds the given message to the outbound message queue.
     * @param message Message to be added to the outbound queue.
     * @return 0 on successful addition and -1 if the session is already closed.
    */
    int comm_session::send(std::string_view message)
    {
        // Making a copy of the message before it is destroyed from the parent scope.
        std::string msg(message);

        if (state == SESSION_STATE::CLOSED)
            return -1;

        // Passing the ownership of msg to the queue using move operator for memory efficiency.
        out_msg_queue.enqueue(std::move(msg));

        return 0;
    }

    /**
     * This function constructs and sends the message to the node from the given message.
     * @param message Message to be sent via the pipe.
     * @return 0 on successful message sent and -1 on error.
    */
    int comm_session::process_outbound_message(std::string_view message)
    {
        // Prepare the memory segments to map with writev().
        iovec memsegs[2];
        uint8_t header_buf[SIZE_HEADER_LEN] = {0, 0, 0, 0, 0, 0, 0, 0};

        if (is_binary)
        {
            // In binary mode, we need to prefix every message with the message size header.
            uint32_t len = message.length();

            // Reserve the first 4 bytes for future (TODO).
            header_buf[4] = len >> 24;
            header_buf[5] = (len >> 16) & 0xff;
            header_buf[6] = (len >> 8) & 0xff;
            header_buf[7] = len & 0xff;

            memsegs[0].iov_base = header_buf;
            memsegs[0].iov_len = SIZE_HEADER_LEN;
            memsegs[1].iov_base = (char *)message.data();
            memsegs[1].iov_len = message.length();
        }
        else
        {
            // In text mode, we need to append every message with '\n'
            memsegs[0].iov_base = (char *)message.data();
            memsegs[0].iov_len = message.length();
            memsegs[1].iov_base = (char *)"\n";
            memsegs[1].iov_len = 1;
        }

        if (writev(write_fd, memsegs, 2) == -1)
        {
            LOG_ERROR << errno << ": Session " << uniqueid.substr(0, 10) << " send writev failed.";
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
        {
            if (session_type == SESSION_TYPE::USER)
                user_sess_handler.on_close(*this);
            else
                peer_sess_handler.on_close(*this);
        }

        state = SESSION_STATE::CLOSED;
        ::close(read_fd);
        if (read_fd != write_fd)
            ::close(write_fd);

        // Wait untill both reader & writer threads gracefully stop.
        reader_thread.join();
        writer_thread.join();

        LOG_DEBUG << (session_type == SESSION_TYPE::PEER ? "Peer" : "User") << " session closed: "
                << uniqueid.substr(0, 10) << (is_inbound ? "[in]" : "[out]") << (is_self ? "[self]" : "");
    }

    /**
 * Attempts to construct the full binary message pending to be read. Only relevant for Binary mode.
 * @param available_bytes Count of bytes that is available to read from the client socket.
 * @return  -1 on error and client must be disconnected. 0 if no message data bytes were read. 1 if some
 *          bytes were read but a full message is not yet formed. 2 if a fully formed message has been
 *          read into the read buffer.
 */
    int comm_session::attempt_binary_msg_construction(const size_t available_bytes)
    {
        // If we have previously encountered a size header and we are waiting until all message
        // bytes are received, we must have the expected message size > 0.

        size_t data_bytes = available_bytes;

        // If we are not tracking a previous size header, then we must check for a size header.
        if (expected_msg_size == 0 && available_bytes >= SIZE_HEADER_LEN)
        {
            // Read the size header.
            uint8_t header_buf[SIZE_HEADER_LEN];
            if (read(read_fd, header_buf, SIZE_HEADER_LEN) == -1)
                return -1; // Indicates that we should disconnect the client.

            data_bytes -= SIZE_HEADER_LEN;

            // We are using last 4 bytes (big endian) in the header for the message size.
            uint32_t upcoming_msg_size = (header_buf[4] << 24) + (header_buf[5] << 16) + (header_buf[6] << 8) + header_buf[7];

            // Remember the expected msg size until sufficient bytes are available.
            expected_msg_size = upcoming_msg_size;
            read_buffer.resize(expected_msg_size);
        }

        if (expected_msg_size > 0 && data_bytes > 0)
        {
            // Claculate bytes remaining to form complete message.
            const size_t remaining_len = expected_msg_size - read_buffer_filled_size;

            // We know expected message size, and enough bytes are available to read complete expected message.
            if (data_bytes >= remaining_len)
            {
                // Complete the buffer by reading remaining bytes.
                if (read(read_fd, read_buffer.data() + read_buffer_filled_size, remaining_len) == -1)
                    return -1; // Indicates that we should disconnect the client.
                read_buffer_filled_size += remaining_len;

                const size_t read_len = expected_msg_size;
                expected_msg_size = 0; // reset the expected msg size.

                return 2; // Full message has been read.
            }
            else
            {
                // Collect any available bytes to the buffer.
                if (read(read_fd, read_buffer.data() + read_buffer_filled_size, data_bytes) == -1)
                    return -1; // Indicates that we should disconnect the client.
                read_buffer_filled_size += data_bytes;

                return 1; // Some bytes were read, but full message is not yet formed.
            }
        }

        return 0; // No message data bytes was read.
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
                this->close();

                t.timestamp = 0;
                t.counter_value = 0;

                LOG_INFO << "Session " << this->uniqueid << " threshold exceeded. (type:" << threshold_type << " limit:" << t.threshold_limit << ")";
                corebill::report_violation(this->address);
            }
            else if (elapsed_time > t.intervalms)
            {
                t.timestamp = time_now;
                t.counter_value = amount;
            }
        }
    }

} // namespace comm