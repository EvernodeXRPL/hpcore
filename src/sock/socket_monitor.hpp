#ifndef _HP_SOCK_MONITOR_H_
#define _HP_SOCK_MONITOR_H_

#include "../util.hpp"
#include "socket_session.hpp"

namespace sock{

template <class T>
void threshold_monitor(util::SESSION_THRESHOLDS threshold, int64_t threshold_limit, socket_session<T> *session);
}

#endif