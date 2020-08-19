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
    constexpr uint32_t READ_BUFFER_IDLE_SIZE = 64 * 1024;

    // Global instances of user and peer session handlers.
    usr::user_session_handler user_sess_handler;
    p2p::peer_session_handler peer_sess_handler;

    comm_session::comm_session(
        std::string_view ip, const int read_fd, const int write_fd, const SESSION_TYPE session_type,
        const bool is_binary, const bool is_inbound, const uint64_t (&metric_thresholds)[4])

        : read_fd(read_fd),
          write_fd(write_fd),
          session_type(session_type),
          uniqueid(std::to_string(read_fd).append(":").append(ip)),
          is_binary(is_binary),
          is_inbound(is_inbound)
    {
        // Create new session_thresholds and insert it to thresholds vector.
        // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
        // since enum's value is used as index in the vector to update vector values.
        thresholds.reserve(4);
        for (size_t i = 0; i < 4; i++)
            thresholds.push_back(session_threshold(metric_thresholds[i], INTERVALMS));
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
 * @param max_msg_size The allowed max byte length of a message to be read.
 * @return  -1 on error and client must be disconnected. 0 if no message data bytes were read. 1 if some
 *          bytes were read but a full message is not yet formed. 2 if a fully formed message has been
 *          read into the read buffer.
 */
    int comm_session::attempt_read(const uint64_t max_msg_size)
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
            if (is_binary)
            {
                res = get_binary_msg_read_len(available_bytes);
            }
            else
            {
                read_buffer.resize(available_bytes);
                res = read(read_fd, read_buffer.data(), available_bytes) < available_bytes ? -1 : 2;
            }

            if (res == 2) // Full message has been read into read buffer.
            {
                res = on_message(std::string_view(read_buffer.data(), read_buffer.size()));

                // Reset the read buffer.
                if (read_buffer.size() > READ_BUFFER_IDLE_SIZE)
                {
                    read_buffer.resize(READ_BUFFER_IDLE_SIZE);
                    read_buffer.shrink_to_fit(); // This is to avaoid large idle memory allocations.
                }

                read_buffer.clear();
                read_buffer_filled_size = 0;
            }
        }

        return res;
    }

    int comm_session::on_message(std::string_view message)
    {
        increment_metric(SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, message.length());

        if (session_type == SESSION_TYPE::USER)
            return user_sess_handler.on_message(*this, message);
        else
            return peer_sess_handler.on_message(*this, message);
    }

    int comm_session::send(const std::vector<uint8_t> &message) const
    {
        std::string_view sv(reinterpret_cast<const char *>(message.data()), message.size());
        send(sv);
    }

    int comm_session::send(std::string_view message) const
    {
        if (state == SESSION_STATE::CLOSED)
            return -1;

        // Prepare the memory segments to map with writev().
        iovec memsegs[2];

        if (is_binary)
        {
            // In binary mode, we need to prefix every message with the message size header.
            uint8_t header_buf[SIZE_HEADER_LEN] = {0, 0, 0, 0, 0, 0, 0, 0};
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
            LOG_ERR << errno << ": Session " << uniqueid << " send writev failed.";
            return -1;
        }
        return 0;
    }

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

        ::close(read_fd);
        state = SESSION_STATE::CLOSED;

        LOG_DBG << (session_type == SESSION_TYPE::PEER ? "Peer" : "User") << " session closed: "
                << uniqueid << (is_inbound ? "[in]" : "[out]") << (is_self ? "[self]" : "");
    }

    /**
 * Retrieves the length of the binary message pending to be read. Only relevant for Binary mode.
 * @param available_bytes Count of bytes that is available to read from the client socket.
 * @return  -1 on error and client must be disconnected. 0 if no message data bytes were read. 1 if some
 *          bytes were read but a full message is not yet formed. 2 if a fully formed message has been
 *          read into the read buffer.
 */
    int comm_session::get_binary_msg_read_len(const size_t available_bytes)
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