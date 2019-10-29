#include "../util.hpp"
#include "socket_session.hpp"

namespace sock{

template <class T>
void threshold_monitor(util::SESSION_THRESHOLDS threshold, std::int64_t threshold_limit, socket_session<T> *session);
}