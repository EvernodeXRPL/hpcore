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
constexpr uint8_t SIZE_HEADER_LEN = 4;

// Global instances of user and peer session handlers.
usr::user_session_handler user_sess_handler;
p2p::peer_session_handler peer_sess_handler;

comm_session::comm_session(
    std::string_view ip, const int fd, const int write_fd, const SESSION_TYPE session_type,
    const bool is_binary, const bool is_self, const bool is_inbound, const uint64_t (&metric_thresholds)[4])

    : session_fd(fd),
      write_fd(write_fd),
      session_type(session_type),
      uniqueid(std::to_string(fd).append(":").append(ip)),
      is_binary(is_binary),
      is_self(is_self),
      is_inbound(is_inbound)
{

    // Create new session_thresholds and insert it to thresholds vector.
    // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
    // since enum's value is used as index in the vector to update vector values.
    thresholds.reserve(sizeof metric_thresholds);
    for (size_t i = 0; i < sizeof metric_thresholds; i++)
        thresholds.push_back(session_threshold(metric_thresholds[i], INTERVALMS));
}

void comm_session::on_connect()
{
    state = SESSION_STATE::ACTIVE;

    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_connect(*this);
    else
        peer_sess_handler.on_connect(*this);
}

/**
 * Attempts to read message data from the given socket fd and passes the message on to the session.
 * @param should_disconnect Whether the client fd must be disconnected.
 * @param max_msg_size The allowed max byte length of a message to be read.
 */
void comm_session::attempt_read(bool &should_disconnect, const uint64_t max_msg_size)
{
    size_t available_bytes = 0;
    if (ioctl(session_fd, FIONREAD, &available_bytes) == -1 || available_bytes == 0 ||
        (max_msg_size > 0 &&
         available_bytes > (max_msg_size + (is_binary ? SIZE_HEADER_LEN : 0))))
    {
        should_disconnect = true;
        return;
    }

    // Keep reading messages until we exhaust all the currently available bytes.
    while (available_bytes > 0)
    {
        const uint32_t read_len = is_binary ? get_binary_msg_read_len(available_bytes) : available_bytes;

        if (read_len == -1)
        {
            should_disconnect = true;
            return;
        }
        else if (read_len > 0)
        {
            available_bytes -= read_len;
            if (is_binary)
                available_bytes -= SIZE_HEADER_LEN;

            char msg_buf[read_len];
            if (read(session_fd, msg_buf, read_len) == -1)
            {
                should_disconnect = true;
                return;
            }

            on_message(msg_buf);
        }
    }
}

void comm_session::on_message(std::string_view message)
{
    increment_metric(SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, message.length());

    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_message(*this, message);
    else
        user_sess_handler.on_message(*this, message);
}

void comm_session::send(std::string_view message) const
{
    // Prepare the memory segments to map with writev().
    iovec memsegs[2];

    if (is_binary)
    {
        // In binary mode, we need to prefix every message with the message size header.
        char size_buf[4];
        uint32_t len = message.length();
        size_buf[0] = len >> 24;
        size_buf[1] = (len >> 16) & 0xff;
        size_buf[2] = (len >> 8) & 0xff;
        size_buf[3] = len & 0xff;

        memsegs[0].iov_base = size_buf;
        memsegs[0].iov_len = 4;
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

    const int fd = write_fd > 0 ? write_fd : session_fd;
    if (writev(fd, memsegs, 2) == -1)
        LOG_ERR << errno << ": Session " << uniqueid << " send writev failed.";
}

void comm_session::close()
{
    if (state = SESSION_STATE::CLOSED)
        return;

    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_close(*this);
    else
        peer_sess_handler.on_close(*this);

    ::close(session_fd);
    state = SESSION_STATE::CLOSED;
}

/**
 * Retrieves the length of the binary message pending to be read. Only relevant for Binary mode.
 * @param available_bytes Count of bytes that is available to read from the client socket.
 * @return Length of the message if the complete message available to be read. 0 if reading must be skipped. -1 if client must be disconnected.
 */
uint32_t comm_session::get_binary_msg_read_len(const size_t available_bytes)
{
    // If we have previously encountered a size header and we are waiting until all message
    // bytes are received, we must have the expected message size > 0.

    // If we are not tracking a previous size header, then we must check for a size header.
    if (expected_msg_size == 0 && available_bytes >= SIZE_HEADER_LEN)
    {
        // Read the size header.
        char header_buf[SIZE_HEADER_LEN];
        if (read(session_fd, header_buf, SIZE_HEADER_LEN) == -1)
            return -1; // Indicates that we should disconnect the client.

        // We are using 4 bytes (big endian) header for the message size.
        expected_msg_size = (header_buf[0] << 24) + (header_buf[1] << 16) + (header_buf[2] << 8) + header_buf[3];

        // We must read the entire message if all message bytes are available.
        if (available_bytes >= SIZE_HEADER_LEN + expected_msg_size)
        {
            expected_msg_size = 0; // reset the expected msg size.
            return expected_msg_size;
        }
    }
    else if (expected_msg_size > 0 && available_bytes >= expected_msg_size)
    {
        // We know expected message size, and enough bytes are available to read complete expected message.
        return expected_msg_size;
    }

    // Skip reading.
    return 0;
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