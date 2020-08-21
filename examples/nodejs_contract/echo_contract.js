const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const hpc = new HotPocketContract();

//console.log("===Echo contract started===");

// We just save execution timestamp as an example state file change.
if (!hpc.readonly)
    fs.appendFileSync("exects.txt", "ts:" + hpc.timestamp + "\n");

Object.keys(hpc.users).forEach(function (key) {

    const user = hpc.users[key];
    user.readInput().then(inputBuf => {
        if (inputBuf) {
            const userInput = inputBuf.toString("utf8");

            if (userInput == "ts")
                user.sendOutput(fs.readFileSync("exects.txt"));
            else
                user.sendOutput("Echoing: " + userInput);
        }
    })
});

//console.log("===Echo contract ended===");
