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
#include "conf.hpp"
#include "hplog.hpp"

namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace src = boost::log::sources;
namespace expr = boost::log::expressions;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;

namespace hplog
{

/**
 * Stream operator overload for converting integer severity vaue to text.
 */
std::ostream &operator<<(std::ostream &os, LOG_SEVERITY level)
{
    static std::string_view loglevels[] = {"dbg", "info", "warn", "err"};
    os << loglevels[level];
    return os;
}

// Severity attribute value tag type
struct severity_tag;

void init()
{
    // Set log severity level based on contract config.
    LOG_SEVERITY severity = LOG_SEVERITY::WARN;
    if (conf::cfg.loglevel == "debug")
        severity = LOG_SEVERITY::DEBUG;
    else if (conf::cfg.loglevel == "info")
        severity = LOG_SEVERITY::INFO;
    else if (conf::cfg.loglevel == "warn")
        severity = LOG_SEVERITY::WARN;
    else if (conf::cfg.loglevel == "error")
        severity = LOG_SEVERITY::ERROR;

    if (conf::cfg.loggers.count("console") == 1)
    {
        logging::add_console_log(
            std::clog,
            keywords::filter = (a_severity >= severity),
            keywords::format =
                (expr::stream
                 << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S")
                 //<< ":" << expr::attr<boost::log::attributes::current_thread_id::value_type>("ThreadID")
                 << " [" << expr::attr<std::string>("Channel")
                 << "] [" << expr::attr<LOG_SEVERITY, severity_tag>("Severity")
                 << "] " << expr::smessage));
    }

    if (conf::cfg.loggers.count("file") == 1)
    {
        // TODO: Add file logger.
    }

    // Add Boost Log built-in fields for log entries.
    logging::add_common_attributes();
}

} // namespace hplog