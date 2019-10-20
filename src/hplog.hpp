#ifndef _HP_HPLOG_H_
#define _HP_HPLOG_H_

#include <iostream>
#include <string>
#include <boost/log/core.hpp>
#include <boost/log/expressions/keyword.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include "conf.hpp"

namespace src = boost::log::sources;
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

void init();

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

#endif