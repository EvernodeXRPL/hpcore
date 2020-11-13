const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

//console.log("===Echo contract started===");

const hpc = new HotPocketContract();
hpc.events.on("exec", ctx => {

    // We just save execution timestamp as an example state file change.
    if (!ctx.readonly)
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

    ctx.events.on("user_message", async (pubKey, message) => {
        const userInput = message.toString("utf8");
        const user = ctx.users[pubKey];
        if (userInput == "ts") {
            user.send(fs.readFileSync("exects.txt"));
        }
        else {
            user.send("Echoing: " + userInput);
        }
    });

    ctx.events.on("all_users_completed", () => {
        ctx.terminate();
    });

    // Npl message sending and receiving template.
    // ctx.events.on("npl_message", (peerPubKey, msg) => {
    //     console.log(msg);
    // });
    // ctx.sendNplMessage(msg);

    // Developer should run method after all the event subscriptions are done.
    ctx.run();
});

// Developer should call init method after all the event subscriptions are done.
hpc.init();

//console.log("===Echo contract ended===");
