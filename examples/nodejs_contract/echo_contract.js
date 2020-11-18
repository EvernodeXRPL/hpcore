const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

// HP smart contract is defined as a function which takes HP ExecutionContext as an argument.
// HP considers execution as complete, when this function completes and all the user message callbacks are complete.
const echoContract = (ctx) => {

    // We just save execution timestamp as an example state file change.
    if (!ctx.readonly)
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

    ctx.users.onMessage(async (user, buf) => {

        // This user's pubkey can be accessed from 'user.pubKey'
        // A reply message can be sent to the user by 'user.send(msg)'

        const msg = buf.toString("utf8");
        if (msg == "ts") {
            await user.send(fs.readFileSync("exects.txt"));
        }
        else {
            await user.send("Echoing: " + msg);
        }
    });    

    // Get list of all users who are connected.
    // ctx.users.get();

    // Get the user identified by public key.
    // ctx.users.find("<PubkeyHex>");

    // Get list of all peers in the cluster.
    // ctx.peers.get();

    // Get the peer identified by public key.
    // ctx.peers.find("<PubkeyHex>");

    // Peer messages example.
    // if (!ctx.readonly) {
    //     ctx.peers.onMessage((peer, msg) => {
    //         console.log(msg + " from " + peer.pubKey);
    //     })
    //     await ctx.peers.send("Hello");
    // }
}

const hpc = new HotPocketContract();
hpc.init(echoContract);