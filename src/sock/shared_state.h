#include <memory>
#include <string>
#include <unordered_set>

// Forward declaration
class server_session;

// Represents the shared server state
class shared_state
{
    // This simple method of tracking
    // sessions only works with an implicit
    // strand (i.e. a single-threaded server)
    std::unordered_set<server_session*> sessions_;

public:

    void join  (server_session& session);
    void leave (server_session& session);
    void send  (std::string message);
};
