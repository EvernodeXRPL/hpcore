#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio.hpp>

#include "../sock/socket_server.hpp"
#include "../sock/socket_client.hpp"
#include "peer_session_handler.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "../usr/usr.hpp"

#include "p2p.hpp"

namespace p2p
{

peer_context peer_ctx;
consensus_context consensus_ctx;
peer_session_handler peer_session_manager;

void open_listen()
{

    auto address = net::ip::make_address("0.0.0.0");
    net::io_context ioc;

    // std::make_shared<sock::socket_server>(
    //     ioc,
    //     tcp::endpoint{address, 22860},
    //     peer_session_manager)
    //     ->run();

    std::make_shared<sock::socket_client>(ioc, peer_session_manager)->run((conf::cfg.listenip).c_str(), "22860");

    std::thread run_thread([&] { ioc.run(); });
    int t;
    std::cin >> t;
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