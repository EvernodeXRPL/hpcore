#ifndef _HP_PCHHEADER_
#define _HP_PCHHEADER_

// Enable boost strack trace.
#define BOOST_STACKTRACE_USE_BACKTRACE

#include <blake3.h>
#include <boost/stacktrace.hpp>
#include <chrono>
#include <concurrentqueue.h>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <flatbuffers/flatbuffers.h>
#include <ftw.h>
#include <iomanip>
#include <iostream>
#include <jsoncons/json.hpp>
#include <jsoncons_ext/bson/bson.hpp>
#include <libgen.h>
#include <list>
#include <math.h>
#include <memory>
#include <mutex>
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>
#include <poll.h>
#include <queue>
#include <readerwriterqueue/readerwriterqueue.h>
#include <set>
#include <shared_mutex>
#include <sodium.h>
#include <sqlite3.h>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#endif