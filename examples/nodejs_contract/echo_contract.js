const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const echoContract = async (ctx) => {

    // We just save execution timestamp as an example state file change.
    if (!ctx.readonly)
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

    await ctx.users.consumeMessages((user, msg) => {
        const userInput = msg.toString("utf8");
        if (userInput == "ts") {
            user.send(fs.readFileSync("exects.txt"));
        }
        else {
            user.send("Echoing: " + userInput);
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