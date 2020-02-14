#include "../pchheader.hpp"
#include "../usr/user_session_handler.hpp"
#include "comm_session.hpp"
#include "../hplog.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../bill/corebill.h"

namespace comm
{

constexpr uint32_t INTERVALMS = 60000;

// Global instance of user session handler.
usr::user_session_handler user_sess_handler;

comm_session::comm_session(std::string_view ip, const int fd, const SESSION_TYPE session_type, const SESSION_MODE mode)
    : session_fd(fd),
      session_type(session_type),
      uniqueid(std::to_string(fd).append(":").append(ip)),
      mode(mode)
{

    // Create new session_thresholds and insert it to thresholds vector.
    // Have to maintain the SESSION_THRESHOLDS enum order in inserting new thresholds to thresholds vector
    // since enum's value is used as index in the vector to update vector values.
    thresholds.reserve(4);

    if (session_type == SESSION_TYPE::USER)
    {
        thresholds.push_back(session_threshold(conf::cfg.pubmaxcpm, INTERVALMS));       // MAX_RAWBYTES_PER_MINUTE
        thresholds.push_back(session_threshold(0, INTERVALMS));                         // MAX_DUPMSGS_PER_MINUTE
        thresholds.push_back(session_threshold(0, INTERVALMS));                         // MAX_BADSIGMSGS_PER_MINUTE
        thresholds.push_back(session_threshold(conf::cfg.pubmaxbadmpm, INTERVALMS));    // MAX_BADMSGS_PER_MINUTE
    }
    else
    {
        thresholds.push_back(session_threshold(conf::cfg.peermaxcpm, INTERVALMS));      // MAX_RAWBYTES_PER_MINUTE
        thresholds.push_back(session_threshold(conf::cfg.peermaxdupmpm, INTERVALMS));   // MAX_DUPMSGS_PER_MINUTE
        thresholds.push_back(session_threshold(conf::cfg.peermaxbadsigpm, INTERVALMS)); // MAX_BADSIGMSGS_PER_MINUTE
        thresholds.push_back(session_threshold(conf::cfg.peermaxbadmpm, INTERVALMS));   // MAX_BADMSGS_PER_MINUTE
    }
}

void comm_session::on_connect()
{
    state = SESSION_STATE::ACTIVE;

    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_connect(*this);
}

void comm_session::on_message(std::string_view message)
{
    increment_metric(SESSION_THRESHOLDS::MAX_RAWBYTES_PER_MINUTE, message.length());

    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_message(*this, message);
}

void comm_session::send(std::string_view message) const
{
    if (mode == SESSION_MODE::TEXT)
    {
        // In text mode, we need to append every message with '\n'
        // Prepare the memory segments to map with writev().
        iovec memsegs[2];
        memsegs[0].iov_base = (char *)message.data();
        memsegs[0].iov_len = message.length();
        memsegs[1].iov_base = (char *)"\n";
        memsegs[1].iov_len = 1;

        if (writev(session_fd, memsegs, 2) == -1)
            LOG_ERR << errno << ": Session send writev failed.";
    }
    else
    {
    }
}

void comm_session::close()
{
    if (session_type == SESSION_TYPE::USER)
        user_sess_handler.on_close(*this);

    ::close(session_fd);
    state = SESSION_STATE::CLOSED;
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