#include "../pchheader.hpp"
#include "self_comm_session.hpp"

namespace comm
{
    self_comm_session::self_comm_session() : comm_session("self", true)
    {
    }

    /**
     * Processes the next queued message (if any).
     * @return 0 if no messages in queue. 1 if message was processed. -1 means there was an error processing the message.
     */
    int self_comm_session::process_next_inbound_message()
    {
        std::string msg;
        if (msg_queue.try_dequeue(msg))
        {
            const int sess_handler_result = peer_sess_handler.on_message(*this, msg);

            // If session handler returns >= 0 it's considered message processing is successful.
            return sess_handler_result == -1 ? -1 : 1;
        }

        return 0;
    }

    int self_comm_session::send(const std::vector<uint8_t> &message)
    {
        std::string_view sv(reinterpret_cast<const char *>(message.data()), message.size());
        send(sv);
        return 0;
    }

    /**
     * Adds the given message to the message queue.
     * @param message Message to be added to the outbound queue.
     * @return 0 on successful addition. -1 on failure.
    */
    int self_comm_session::send(std::string_view message)
    {
        // Passing the ownership of message to the queue.
        msg_queue.enqueue(std::string(message));
        return 0;
    }

} // namespace comm