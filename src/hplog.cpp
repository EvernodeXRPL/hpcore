#include "pchheader.hpp"
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
 * Stream operator overload for converting integer severity value to text.
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

    // Log line format expression.
    const auto format_expr = (expr::stream
                        << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S")
                        //<< ":" << expr::attr<boost::log::attributes::current_thread_id::value_type>("ThreadID")
                        << " [" << expr::attr<std::string>("Channel")
                        << "] [" << expr::attr<LOG_SEVERITY, severity_tag>("Severity")
                        << "] " << expr::smessage);

    if (conf::cfg.loggers.count("console") == 1)
    {
        logging::add_console_log(
            std::clog,
            keywords::filter = (a_severity >= severity),
            keywords::format = format_expr);
    }

    if (conf::cfg.loggers.count("file") == 1)
    {
        logging::add_file_log(
            keywords::target = conf::ctx.log_dir,                   // Log file directory.
            keywords::file_name = conf::ctx.log_dir + "/hp_%N.log", // File name pattern "hp_1.log".
            keywords::rotation_size = 10 * 1024 * 1024,            // Rotate files every 10 MB.
            keywords::max_size = 500 * 1024 * 1024,                // Do not exceed 500 MB total logs.
            keywords::filter = (a_severity >= severity),
            keywords::format = format_expr,

            // This will make every new launch of Hot Pocket to start a new log file number.
            // It will scan existing log files matching the pattern and find the next number.
            keywords::scan_method = sinks::file::scan_matching

#ifndef NDEBUG
            // We enable auto_flush to immediately get the logs onto the file. Otherwise it takes time
            // for buffered logs to reach the file. This impacts performance. So enabled only in debug build.
            , keywords::auto_flush = true
#endif
        );
    }

    // Add Boost Log built-in fields for log entries.
    logging::add_common_attributes();
}

void deinit()
{
    // This will make all buffered logs to be flushed to the sink.
    logging::core::get()->remove_all_sinks();
}

} // namespace hplog