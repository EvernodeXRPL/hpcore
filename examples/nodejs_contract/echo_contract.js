const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const echoContract = async (ctx) => {

    // We just save execution timestamp as an example state file change.
    if (!ctx.readonly)
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

    await ctx.users.consumeMessages((user, buf) => {
        const msg = buf.toString("utf8");
        if (msg == "ts") {
            user.send(fs.readFileSync("exects.txt"));
        }
        else {
            user.send("Echoing: " + msg);
        }
    });

    // ctx.peers.onMessage((peer, msg) => {

    // })

    // await ctx.peers.send(msg);
}

(async function () {
    const hpc = new HotPocketContract();
    await hpc.init(echoContract);
}());