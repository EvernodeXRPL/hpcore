#ifndef _HP_PCHHEADER_
#define _HP_PCHHEADER_

// Enable boost strack trace.
#define BOOST_STACKTRACE_USE_BACKTRACE
// Enable custom handlers for boost assertion failures.
#define BOOST_ENABLE_ASSERT_DEBUG_HANDLER

#include <bitset>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/expressions/keyword.hpp>
#include <boost/log/expressions/keyword_fwd.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/manipulators/to_log.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/stacktrace.hpp>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libgen.h>
#include <list>
#include <math.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <queue>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/ostreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/schema.h>
#include <set>
#include <sodium.h>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#endif