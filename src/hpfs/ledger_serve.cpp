
#include "./ledger_serve.hpp"

namespace hpfs
{
    void ledger_serve::swap_collected_requests()
    {
        std::scoped_lock<std::mutex> lock(p2p::ctx.collected_msgs.ledger_hpfs_requests_mutex);

        // Move collected hpfs requests for contract fs over to local requests list.
        if (!p2p::ctx.collected_msgs.ledger_hpfs_requests.empty())
            hpfs_requests.splice(hpfs_requests.end(), p2p::ctx.collected_msgs.ledger_hpfs_requests);
    }
} // namespace hpfs