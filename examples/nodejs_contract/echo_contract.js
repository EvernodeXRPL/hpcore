const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const hpc = new HotPocketContract();

//console.log("===Echo contract started===");

// We just save execution timestamp as an example state file change.
if (!hpc.readonly)
    fs.appendFileSync("exects.txt", "ts:" + hpc.timestamp + "\n");

Object.keys(hpc.users).forEach((key) => {
    const user = hpc.users[key];
    user.events.on('message', (msg) => {
        if (msg) {
            const userInput = msg.toString("utf8");
            if (userInput == "ts") {
                user.sendOutput(fs.readFileSync("exects.txt"));
                user.closeChannel();
            }
            else {
                user.sendOutput("Echoing: " + userInput);
                user.closeChannel();
            }
        }
    });
});

const npl = hpc.npl;

// Npl channel always connected if contract is not in readonly mode.
// Smart contract developer has to mannually close the channel once the execution logic is complete.
if (npl) {
    npl.closeNplChannel();
}

// HP <--> SC
const hp = hpc.control;
hp.closeControlChannel();

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
