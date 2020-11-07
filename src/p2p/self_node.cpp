#include "../pchheader.hpp"
#include "peer_session_handler.hpp"

namespace p2p::self
{
    // Holds self messages waiting to be processed.
    moodycamel::ConcurrentQueue<std::string> msg_queue;

    void process_next_message()
    {
        std::string msg;
        if (msg_queue.try_dequeue(msg))
            p2p::handle_self_message(msg);
    }

    void send(const std::vector<uint8_t> &message)
    {
        std::string_view sv(reinterpret_cast<const char *>(message.data()), message.size());
        send(sv);
    }

    void send(std::string_view message)
    {
        // Passing the ownership of message to the queue.
        msg_queue.enqueue(std::string(message));
    }

} // namespace p2p::self