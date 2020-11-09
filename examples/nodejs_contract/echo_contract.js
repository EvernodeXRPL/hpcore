const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const hpc = new HotPocketContract();

//console.log("===Echo contract started===");

// We just save execution timestamp as an example state file change.
if (!hpc.readonly)
    fs.appendFileSync("exects.txt", "ts:" + hpc.timestamp + "\n");

hpc.events.on("user_message", async (pubKey, message) => {
    const userInput = message.toString("utf8");
    const user = hpc.users[pubKey];
    if (userInput == "ts") {
        user.sendOutput(fs.readFileSync("exects.txt"));
    }
    else {
        user.sendOutput("Echoing: " + userInput);
    }
});

hpc.events.on("all_users_completed", () => {
    hpc.terminate();
});

// Developer should call run method after all the event subscriptions are done.
hpc.run();

// Control message sending and receiving template.
// const hp = hpc.control;
// hpc.events.on('control_message', (msg) => {
//     console.log('control msg - ' + msg);
//     hp.sendOutput(msg);
// })

// Npl message sending and receiving template.
// const npl = hpc.npl;
// if (npl) {
//     let i = 0;
//     let interval = setInterval(() => {
//         npl.sendOutput(`npl${i} from contract`);
//         if (i == 5) {
//             clearInterval(interval);
//         }
//         i++;
//     }, 500);

//     hpc.events.on("npl_message", msg => {
//         if (msg) {
//             console.log(msg);
//         }
//     });
// }

//console.log("===Echo contract ended===");
