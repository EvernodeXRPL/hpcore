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

    // Broadcast message to all connected users.
    // ctx.users.get().forEach(u => u.send("Hello"));

    // Send message to specific user (identified by public key).
    // await ctx.users.find(<PubkeyHex>).send("Hello");

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