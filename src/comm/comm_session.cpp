#include "../pchheader.hpp"
#include "comm_session.hpp"

namespace comm
{
    comm_session::comm_session(std::string_view id, const bool is_self)
        : uniqueid(id),
          is_self(is_self)
    {
    }

    /**
     * Returns printable name for the session based on uniqueid (used for logging).
     */
    const std::string comm_session::display_name()
    {
        return uniqueid;
    }

    void comm_session::set_threshold(const SESSION_THRESHOLDS threshold_type, const uint64_t threshold_limit, const uint32_t intervalms)
    {
    }

    void comm_session::increment_metric(const SESSION_THRESHOLDS threshold_type, const uint64_t amount)
    {
    }

} // namespace comm