#include "../pchheader.hpp"
#include "../conf.hpp"
#include "p2p.hpp"
#include "../msg/fbuf/p2pmsg_generated.h"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../msg/fbuf/common_helpers.hpp"

namespace p2pmsg = msg::fbuf::p2pmsg;

namespace p2p::self
{
    // Holds self messages waiting to be processed.
    moodycamel::ConcurrentQueue<std::string> msg_queue;

    std::optional<conf::peer_ip_port> ip_port;

    /**
     * Processes the next queued message (if any).
     * @return 0 if no messages in queue. 1 if message was processed successfully. -1 on error.
     */
    int process_next_message()
    {
        std::string msg;
        if (msg_queue.try_dequeue(msg))
        {
            // Handle the message we received from ourselves.
            const peer_message_info mi = p2pmsg::get_peer_message_info(msg);

            if (mi.type == p2pmsg::P2PMsgContent_ProposalMsg)
                handle_proposal_message(p2pmsg::create_proposal_from_msg(mi, hash_proposal_msg(*mi.p2p_msg->content_as_ProposalMsg())));
            else if (mi.type == p2pmsg::P2PMsgContent_NonUnlProposalMsg)
                handle_nonunl_proposal_message(p2pmsg::create_nonunl_proposal_from_msg(mi));
            else if (mi.type == p2pmsg::P2PMsgContent_NplMsg)
                handle_npl_message(p2pmsg::create_npl_from_msg(mi));
        }

        return 0;
    }

    void send(std::string_view message)
    {
        // Passing the ownership of message to the queue.
        msg_queue.enqueue(std::string(message));
    }

} // namespace p2p::self