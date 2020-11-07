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

} // namespace comm