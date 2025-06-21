#include "../pchheader.hpp"
#include "../conf.hpp"
#include "p2p.hpp"
#include "../msg/fbuf/p2pmsg_generated.h"
#include "../msg/fbuf/p2pmsg_conversion.hpp"
#include "../msg/fbuf/common_helpers.hpp"
#include "../util/bloom_filter.hpp"
#include "../crypto.hpp"

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
            {
                handle_proposal_message(p2pmsg::create_proposal_from_msg(mi, hash_proposal_msg(*mi.p2p_msg->content_as_ProposalMsg())));
            }
            else if (mi.type == p2pmsg::P2PMsgContent_NonUnlProposalMsg)
            {
                handle_nonunl_proposal_message(p2pmsg::create_nonunl_proposal_from_msg(mi));
            }
            else if (mi.type == p2pmsg::P2PMsgContent_NplMsg)
            {
                // For self messages, we perform duplicate checks for NPL messages.

                // Messages larger than the duplicate message threshold is ignored from the duplicate message check
                // due to the overhead in hash generation for larger messages.
                if (msg.size() <= conf::MAX_SIZE_FOR_DUP_CHECK && !recent_selfmsg_hashes.try_emplace(crypto::get_hash(msg)))
                {
                    LOG_DEBUG << "Duplicate self npl message.";
                    return 0;
                }

                handle_npl_message(p2pmsg::create_npl_from_msg(mi));
            }
        }

        return 0;
    }

    void send(std::string_view message)
    {
        // Passing the ownership of message to the queue.
        msg_queue.enqueue(std::string(message));
    }

} // namespace p2p::self
