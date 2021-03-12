#include "../pchheader.hpp"
#include "peer_session_handler.hpp"

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
            return p2p::handle_self_message(msg);

        return 0;
    }

    void send(std::string_view message)
    {
        // Passing the ownership of message to the queue.
        msg_queue.enqueue(std::string(message));
    }

} // namespace p2p::self