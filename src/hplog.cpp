#include "pchheader.hpp"
#include "conf.hpp"

namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace src = boost::log::sources;
namespace expr = boost::log::expressions;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;

namespace hplog
{
    constexpr size_t MAX_TRACE_FILESIZE = 10 * 1024 * 1024; // Maximum file size (10MB)
    constexpr size_t MAX_TRACE_FILECOUNT = 50; // Maximum files in a folder

    class plog_formatter;
    static plog::ConsoleAppender<plog_formatter> consoleAppender;

    // Custom formatter adopted from:
    // https://github.com/SergiusTheBest/plog/blob/master/include/plog/Formatters/TxtFormatter.h
    class plog_formatter
    {
    public:
        static plog::util::nstring header()
        {
            return plog::util::nstring();
        }

        static plog::util::nstring format(const plog::Record &record)
        {
            tm t;
            plog::util::localtime_s(&t, &record.getTime().time); // local time

            plog::util::nostringstream ss;
            ss << t.tm_year + 1900 << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_mon + 1 << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_mday << PLOG_NSTR(" ");
            ss << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_hour << PLOG_NSTR(":") << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_min << PLOG_NSTR(":") << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_sec << PLOG_NSTR(" ");
            ss << PLOG_NSTR("[") << conf::cfg.loglevel << PLOG_NSTR("][hp] ");
            ss << record.getMessage() << PLOG_NSTR("\n");

            return ss.str();
        }
    };

    int init()
    {
        // Skip plog initialization if log severity is configured as none.
        conf::LOG_SEVERITY log_severity = conf::get_log_severity_type(conf::cfg.loglevel);
        if (log_severity == conf::LOG_SEVERITY::NONE)
            return 0;

        plog::Severity level;
        if (log_severity == conf::LOG_SEVERITY::DEBUG)
            level = plog::Severity::debug;
        else if (log_severity == conf::LOG_SEVERITY::INFO)
            level = plog::Severity::info;
        else if (log_severity == conf::LOG_SEVERITY::WARN)
            level = plog::Severity::warning;
        else if (log_severity == conf::LOG_SEVERITY::ERROR)
            level = plog::Severity::error;
        else if (log_severity == conf::LOG_SEVERITY::FATEL)
            level = plog::Severity::fatal;
        else if (log_severity == conf::LOG_SEVERITY::VERBOSE)
            level = plog::Severity::verbose;
        else
            return -1;

        std::string pid_str = std::to_string(getpid());
        std::string trace_file;
        trace_file
            .append(conf::ctx.log_dir)
            .append("/hp_%N.log");

        plog::init<plog_formatter>(level, trace_file.c_str(), MAX_TRACE_FILESIZE, MAX_TRACE_FILECOUNT)
            .addAppender(&consoleAppender);

        return 0;
    }
} // namespace hplog