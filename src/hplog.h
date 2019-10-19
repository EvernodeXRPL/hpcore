#include <iostream>
#include <string>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/expressions/keyword_fwd.hpp>
#include <boost/log/expressions/keyword.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/manipulators/to_log.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>

namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace src = boost::log::sources;
namespace expr = boost::log::expressions;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;

namespace hplog
{

enum LOG_SEVERITY
{
    DEBUG,
    INFO,
    WARN,
    ERROR
};

BOOST_LOG_ATTRIBUTE_KEYWORD(a_severity, "Severity", hplog::LOG_SEVERITY);

// The operator is used for regular stream formatting
std::ostream &operator<<(std::ostream &strm, LOG_SEVERITY level)
{
    static const char *strings[] =
        {
            "dbg",
            "info",
            "warn",
            "err"};

    if (static_cast<std::size_t>(level) < sizeof(strings) / sizeof(*strings))
        strm << strings[level];
    else
        strm << static_cast<int>(level);

    return strm;
}

// Severity attribute value tag type
struct severity_tag;

void init()
{
    logging::add_console_log(
        std::clog,
        keywords::filter = (a_severity >= LOG_SEVERITY::WARN),
        keywords::format =
            (expr::stream
             << expr::format_date_time< boost::posix_time::ptime >("TimeStamp", "%Y-%m-%d %H:%M:%S")
             //<< ":" << expr::attr<boost::log::attributes::current_thread_id::value_type>("ThreadID")
             << " [" << expr::attr<std::string>("Channel")
             << "] <" << expr::attr<LOG_SEVERITY, severity_tag>("Severity")
             << "> " << expr::smessage));

    logging::add_common_attributes();
}

} // namespace hplog

// Thread-safe global logger type.
typedef src::severity_channel_logger_mt<hplog::LOG_SEVERITY, std::string> logger;

BOOST_LOG_INLINE_GLOBAL_LOGGER_INIT(hplogger, logger)
{
    return logger(keywords::channel = "hp");
}

BOOST_LOG_INLINE_GLOBAL_LOGGER_INIT(sclogger, logger)
{
    return logger(keywords::channel = "sc");
}

#define LOG_DBG BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::DEBUG)
#define LOG_INFO BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::INFO)
#define LOG_WARN BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::WARN)
#define LOG_ERR BOOST_LOG_SEV(hplogger::get(), hplog::LOG_SEVERITY::ERROR)

#define LOG_INFO_SC BOOST_LOG_SEV(sclogger::get(), hplog::LOG_SEVERITY::INFO)
#define LOG_ERR_SC BOOST_LOG_SEV(sclogger::get(), hplog::LOG_SEVERITY::ERROR)
