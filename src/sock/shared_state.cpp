#include "../sock/shared_state.h"
#include "../sock/server_session.h"


void
shared_state::
join(server_session& session)
{
    sessions_.insert(&session);
}

void
shared_state::
leave(server_session& session)
{
    sessions_.erase(&session);
}

void
shared_state::
send(std::string message)
{
    auto const ss = std::make_shared<std::string const>(std::move(message));

    for(auto session : sessions_)
        session->send(ss);
}