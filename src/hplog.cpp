#include "pchheader.hpp"
#include "conf.hpp"
#include "hplog.hpp"

namespace hplog
{
    constexpr size_t MAX_TRACE_FILESIZE = 10 * 1024 * 1024; // Maximum file size (10MB)
    constexpr size_t MAX_TRACE_FILECOUNT = 50;              // Maximum files in a folder

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

        // Take decision to append logger for file / console or both.
        if (conf::cfg.loggers.size() == 2)
        {
            plog::init(level, &fileAppender).addAppender(&consoleAppender);
        }
        else if (conf::cfg.loggers.count("console") == 1)
        {
            plog::init(level, &consoleAppender);
        }
        else
        {
            plog::init(level, &fileAppender);
        }
    }
} // namespace hplog