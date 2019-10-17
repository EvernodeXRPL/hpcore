#include <iostream>
#include <boost/algorithm/string.hpp>
#include "../sock/socket_server.hpp"
#include "../sock/socket_client.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../usr/usr.hpp"
#include "peer_session_handler.hpp"
#include "p2p.hpp"

namespace p2p
{
/**
 * Peer connections exposing to the application
 */
std::unordered_map<std::string, sock::socket_session *> peer_connections;

/**
 * Peer session handler instance. This instance's methods will be fired for any user socket activity.
 */
p2p::peer_session_handler global_peer_session_handler;

/**
 * IO context used by the  boost library in creating sockets
 */
net::io_context ioc;

/**
 * The thread the peer server and client is running on. (not exposed out of this namespace)
 */
std::thread timer_thread;

/**
 * The thread the peer listener is running on. (not exposed out of this namespace)
 */
std::thread peer_thread;

peer_context peer_ctx;
consensus_context consensus_ctx;

int init()
{
    //Entry point for p2p which will start peer connections to other nodes
    start_peer_connections();

    return 0;
}

void start_peer_connections()
{
    auto address = net::ip::make_address(conf::cfg.listenip);

    // Start listening to peers
    std::make_shared<sock::socket_server>(
        ioc,
        tcp::endpoint{address, conf::cfg.peerport},
        global_peer_session_handler)
        ->run();

    std::cout << "Started listening for incoming peer connections on " << conf::cfg.listenip + ":" + std::to_string(conf::cfg.peerport) << std::endl;

    //Scan peers and trying to keep up the connections if drop. This action is run on a seperate thread.
    timer_thread = std::thread([&] { peer_connection_watchdog(); });

    peer_thread = std::thread([&] { ioc.run(); });
}

// Scan peer connections continually and attempt to maintain the connection if they drop
void peer_connection_watchdog()
{
    for (auto &v : conf::cfg.peers)
    {
        if (peer_connections.find(v.first) == peer_connections.end())
        {
            std::cout << "Trying to connect :" << v.second.first + ":" << v.second.second << std::endl;
            std::make_shared<sock::socket_client>(ioc, global_peer_session_handler)->run(v.second.first, v.second.second);
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(conf::cfg.roundtime * 4));
    peer_connection_watchdog();
}

/*

*/
/**
 * Validate the incoming p2p message. Check for message version, timestamp and signature.
 * 
 * @param msg pointer to a string message buffer.
 * @param msg size of the message buffer.
 * @param timestamp of the message.
 * @return whether message is validated or not.
 */
bool validate_peer_message(const std::string *message, size_t message_size, time_t timestamp, uint16_t version)
{
    std::time_t time_now = std::time(nullptr);
    //todo:check pubkey in unl list. need to change unl list to a map.

    //protocol version check
    if (version <= util::MIN_PEERMSG_VERSION)
    {
        std::cout << "recieved message is a old unsupported version" << std::endl;
        return false;
    }
    //check consensus stage
    //check message timestamp < timestamp now - 4* round time.
    if (timestamp < (time_now - conf::cfg.roundtime * 4))
    {
        std::cout << "recieved message from peer is old" << std::endl;
        return false;
    }

    //get message hash and see wheteher message is already recieved -> abandon
    auto messageHash = crypto::sha_512_hash(message, message_size, "PEERMSG", 7);

    if (peer_ctx.recent_peer_msghash.count(messageHash) == 0)
    {
        peer_ctx.recent_peer_msghash.try_emplace(messageHash, timestamp);
    }
    else
    {
        return false;
    }

    //signature check

    return true;
}

// void consensus()
// {
//     std::time_t timestamp = std::time(nullptr);
//     p2p::Proposal proposal;

//     switch (consensus_ctx.stage)
//     {

//     case 0: // in stage 0 we create a novel proposal and broadcast it
//     {
//         // clear out the old stage 3 proposals and any previous proposals made by us
//         // todo: check the state of these to ensure we're running consensus ledger
//         for (const auto &p : consensus_ctx.proposals)
//         {
//             auto propsal = p.second;
//             if (propsal.stage() == 3 || conf::cfg.pubkeyb64 == "propsal pubkey")
//                 consensus_ctx.proposals.erase(p.first);
//         }

//         for (const auto &user : usr::users)
//         {
//             // add all the connections we host
//             proposal.add_connections(user.second.pubkeyb64);

//             // todo:add all their pending messages
//         }

//         // todo:propose outputs from previous round if any
//         // todo: set propsal states

//         consensus_ctx.novel_proposal_time = timestamp;
//         //proposal.time() = static_cast<int> (timestamp); time_t is long int

//         //broadcast_to_peers(sign_peer_message(proposal).signed)
//     }
//     case 1:
//     case 2:
//     case 3:
//     {
//     }
//     }
// }

} // namespace p2p