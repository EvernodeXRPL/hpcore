const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');

const hpc = new HotPocketContract();

//console.log("===Echo contract started===");

// We just save execution timestamp as an example state file change.
if (!hpc.readonly)
    fs.appendFileSync("exects.txt", "ts:" + hpc.timestamp + "\n");

const nplInputs = hpc.npl.readInput();
if (nplInputs) {
    nplInputs.forEach(inp => {
        console.log(inp.pubkey);
        console.log(inp.input.toString());
    });
}
else {
    console.log("Np npl input");
}

hpc.npl.sendOutput("Hello!!");

Object.keys(hpc.users).forEach(function (key) {

    const user = hpc.users[key];
    const inputBuf = user.readInput();
    if (inputBuf) {
        const userInput = inputBuf.toString("utf8");

        // Append user input to a state file if not in read only mode.
        if (!hpc.readonly)
            fs.appendFileSync("userinputs.txt", userInput + "\n");

        if (userInput == "ts")
            user.sendOutput(fs.readFileSync("exects.txt"));
        else
            user.sendOutput("Echoing: " + userInput);
    }
});

//console.log("===Echo contract ended===");
