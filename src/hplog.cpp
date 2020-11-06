#include "pchheader.hpp"
#include "conf.hpp"
#include "hplog.hpp"

namespace hplog
{
    constexpr size_t MAX_TRACE_FILESIZE = 10 * 1024 * 1024; // Maximum file size (10MB)
    constexpr size_t MAX_TRACE_FILECOUNT = 50;              // Maximum files in a folder

    class plog_formatter;

    // Custom formatter adopted from:
    // https://github.com/SergiusTheBest/plog/blob/master/include/plog/Formatters/TxtFormatter.h
    class plog_formatter
    {
    public:
        static plog::util::nstring header()
        {
            return plog::util::nstring();
        }

        static inline const char *severity_to_string(plog::Severity severity)
        {
            switch (severity)
            {
            case plog::Severity::fatal:
                return "fat";
            case plog::Severity::error:
                return "err";
            case plog::Severity::warning:
                return "wrn";
            case plog::Severity::info:
                return "inf";
            case plog::Severity::debug:
                return "dbg";
            case plog::Severity::verbose:
                return "ver";
            default:
                return "def";
            }
        }

        static plog::util::nstring format(const plog::Record &record)
        {
            tm t;
            plog::util::localtime_s(&t, &record.getTime().time); // local time

            plog::util::nostringstream ss;
            ss << t.tm_year + 1900 << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_mon + 1 << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_mday << PLOG_NSTR(" ");
            ss << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_hour << PLOG_NSTR(":")
               << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_min << PLOG_NSTR(":")
               << std::setfill(PLOG_NSTR('0')) << std::setw(2) << t.tm_sec << PLOG_NSTR(" ");
               // Uncomment for millseconds.
               // << std::setfill(PLOG_NSTR('0')) << std::setw(3) << record.getTime().millitm << PLOG_NSTR(" ");

            ss << PLOG_NSTR("[") << severity_to_string(record.getSeverity()) << PLOG_NSTR("][hpc] ");
            ss << record.getMessage() << PLOG_NSTR("\n");

            return ss.str();
        }
    };

    void init()
    {
        plog::Severity level;

        if (conf::cfg.loglevel_type == conf::LOG_SEVERITY::DEBUG)
            level = plog::Severity::debug;
        else if (conf::cfg.loglevel_type == conf::LOG_SEVERITY::INFO)
            level = plog::Severity::info;
        else if (conf::cfg.loglevel_type == conf::LOG_SEVERITY::WARN)
            level = plog::Severity::warning;
        else
            level = plog::Severity::error;

        const std::string trace_file = conf::ctx.log_dir + "/hp.log";
        static plog::RollingFileAppender<plog_formatter> fileAppender(trace_file.c_str(), MAX_TRACE_FILESIZE, MAX_TRACE_FILECOUNT);
        static plog::ConsoleAppender<plog_formatter> consoleAppender;

        plog::Logger<0> &logger = plog::init(level);

        // Take decision to append logger for file / console or both.
        if (conf::cfg.loggers.count("console") == 1)
        {
            logger.addAppender(&consoleAppender);
        }

        if (conf::cfg.loggers.count("file") == 1)
        {
            logger.addAppender(&fileAppender);
        }
    }
} // namespace hplog