const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const hpc = new HotPocketContract();

//console.log("===Echo contract started===");

// We just save execution timestamp as an example state file change.
if (!hpc.readonly)
    fs.appendFileSync("exects.txt", "ts:" + hpc.timestamp + "\n");

Object.keys(hpc.users).forEach(async (key) => {

    const user = hpc.users[key];
    const inputBuf = await user.readInput();
    if (inputBuf) {
        const userInput = inputBuf.toString("utf8");
        console.log(userInput)
        if (userInput == "ts")
            user.sendOutput(fs.readFileSync("exects.txt"));
        else
            user.sendOutput("Echoing: " + userInput);
    }
});

const npl = hpc.npl;

// Npl channel always connected if contract is not in readonly mode.
// Smart contract developer has to mannually close the channel once the execution logic is complete.
if (npl) {
    npl.closeNplChannel();
}

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
