const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const hpc = new HotPocketContract();

//console.log("===Echo contract started===");

// We just save execution timestamp as an example state file change.
if (!hpc.readonly)
    fs.appendFileSync("exects.txt", "ts:" + hpc.timestamp + "\n");

// Utility function to simulate asynchronous behavior.
// let asyncSimulator = (timeout) => {
//     return new Promise(resolve => {
//         setTimeout(() => {
//             resolve();
//         }, timeout);
//     })
// }

hpc.events.on("user_message", async (pubKey, message) => {
    const userInput = message.toString("utf8");
    const user = hpc.users[pubKey];
    // Simulate asynchronous behavior.
    // await asyncSimulator(1000);
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

const npl = hpc.npl;

// Control message sending and receiving template.
// let i = 0;
// hp.events.on('message', (msg) => {
//     console.log('control msg - ' + msg);
//     hp.sendOutput(msg);
//     i++;
//     if (i == 2)
//         hp.closeControlChannel();
// })

// Npl message sending and receiving template.
// if (npl) {
//     let i = 0;
//     let interval = setInterval(() => {
//         npl.sendOutput(`npl${i} from contract`);
//         if (i == 5) {
//             clearInterval(interval);
//             npl.closeNplChannel();
//         }
//         i++;
//     }, 500);

//     npl.events.on("message", msg => {
//         if (msg) {
//             console.log(msg);
//         }
//     });
// }

//console.log("===Echo contract ended===");
