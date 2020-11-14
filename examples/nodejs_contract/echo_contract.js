const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');
const timeout = ms => new Promise(res => setTimeout(res, ms));
//console.log("===Echo contract started===");

const hpc = new HotPocketContract();
hpc.init(events => {
    events.on("exec", (ctx) => {

        ctx.init(events => {
            events.on("user_message", (pubKey, message) => {
                const userInput = message.toString("utf8");
                const user = ctx.users[pubKey];
                if (userInput == "ts") {
                    user.send(fs.readFileSync("exects.txt"));
                }
                else {
                    user.send("Echoing: " + userInput);
                }
            });

            events.on("all_users_completed", () => {

                // We just save execution timestamp as an example state file change.
                if (!ctx.readonly)
                    fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

                // After we finish processing everything we call terminate to exit gracefully.
                ctx.terminate();
            });

            events.on("npl_message", (peerPubKey, msg) => {
                console.log(msg);
            });
        })

        // NPL send example.
        // ctx.sendNplMessage(msg);
    });
});

//console.log("===Echo contract ended===");
