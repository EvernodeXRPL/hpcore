#include "../pchheader.hpp"
#include "peer_session_handler.hpp"

namespace p2p::self
{
    constexpr uint16_t MAX_MSG_QUEUE_SIZE = 96;    // Maximum message queue size, The size passed is rounded up to the next multiple of the block size (32).
    
    // Holds self messages waiting to be processed.
    moodycamel::ConcurrentQueue<std::string> msg_queue(MAX_MSG_QUEUE_SIZE);

    /**
     * Processes the next queued message (if any).
     * @return 0 if no messages in queue. 1 if message was processed successfully. -1 on error.
     */
    int process_next_message()
    {
        std::string msg;
        if (msg_queue.try_dequeue(msg))
            return p2p::handle_self_message(msg);

        return 0;
    }

    /**
     * Add next message to the queue.
     * @return 0 on successful addition and -1 if there's no space in the queue.
     */
    int send(std::string_view message)
    {
        // Passing the ownership of message to the queue.
        return msg_queue.try_enqueue(std::string(message)) ? 0 : -1;
    }

} // namespace p2p::self