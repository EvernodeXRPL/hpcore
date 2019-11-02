#ifndef _HP_HPLOG_
#define _HP_HPLOG_

#include "pchheader.hpp"
#include "conf.hpp"

namespace src = boost::log::sources;
namespace keywords = boost::log::keywords;

namespace hplog
{

// Log severity levels used in Hot Pocket.
enum LOG_SEVERITY
{
    DEBUG,
    INFO,
    WARN,
    ERROR
};

BOOST_LOG_ATTRIBUTE_KEYWORD(a_severity, "Severity", hplog::LOG_SEVERITY);

void init();
void deinit();

} // namespace hplog

// Thread-safe global logger type using custom LOG_SEVERITY enum..
typedef src::severity_channel_logger_mt<hplog::LOG_SEVERITY, std::string> logger;

// hplogger is the log source for Hot Pocket generated logs.
BOOST_LOG_INLINE_GLOBAL_LOGGER_INIT(hplogger, logger)
{
    return logger(keywords::channel = "hp");
}

// sclogger is the log source for logging captured stdour/stderr from smart contract.
BOOST_LOG_INLINE_GLOBAL_LOGGER_INIT(sclogger, logger)
{
    return logger(keywords::channel = "sc");
}

// HP logging macros.
#define LOG_DBG BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::DEBUG)
#define LOG_INFO BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::INFO)
#define LOG_WARN BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::WARN)
#define LOG_ERR BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::ERROR)

// SC stdout/err logging macros.
#define LOG_INFO_SC BOOST_LOG_SEV(sclogger::get(), hplog::LOG_SEVERITY::INFO)
#define LOG_ERR_SC BOOST_LOG_SEV(sclogger::get(), hplog::LOG_SEVERITY::ERROR)

#endif