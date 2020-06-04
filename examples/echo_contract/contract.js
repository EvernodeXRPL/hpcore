process.on('uncaughtException', (err) => {
    console.error('There was an uncaught error', err)
})
const fs = require('fs')

//console.log("===Sample contract started===");
//console.log("Contract args received from hp: " + input);

let hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));

// We just save execution args as an example state file change.
fs.appendFileSync("exects.txt", "ts:" + hpargs.ts + "\n");

Object.keys(hpargs.usrfd).forEach(function (key, index) {
    let userfds = hpargs.usrfd[key];

    if (userfds[0] != -1) {
        let userinput = fs.readFileSync(userfds[0], 'utf8');
        // Append user input to a state file.
        fs.appendFileSync("userinputs.txt", userinput + "\n");
        fs.writeSync(userfds[1], "Echoing: " + userinput);
    }
});

let nplinput = fs.readFileSync(hpargs.nplfd[0], 'utf8');
if (nplinput.length > 0) {
    console.log("Input received from hp:");
    console.log(nplinput);
    fs.writeSync(hpargs.nplfd[1], "Echoing: " + nplinput);
}

let hpinput = fs.readFileSync(hpargs.hpfd[0], 'utf8');
if (hpinput.length > 0) {
    //console.log("Input received from hp:");
    //console.log(hpinput);
    fs.writeSync(hpargs.hpfd[1], "Echoing: " + hpinput);
}

//console.log("===Sample contract ended===");
