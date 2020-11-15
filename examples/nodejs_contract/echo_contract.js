const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const echoContract = (ctx) => {

    // We just save execution timestamp as an example state file change.
    if (!ctx.readonly)
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

    ctx.users.onMessage(async (user, buf) => {
        const msg = buf.toString("utf8");
        if (msg == "ts") {
            await user.send(fs.readFileSync("exects.txt"));
        }
        else {
            await user.send("Echoing: " + msg);
        }
    });

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