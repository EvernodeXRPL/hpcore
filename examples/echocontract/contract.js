process.on('uncaughtException', (err) => {
    console.error('There was an uncaught error', err)
})
const fs = require('fs')

let input = fs.readFileSync(0, 'utf8');
//console.log("===Sample contract started===");
//console.log("Contract args received from hp: " + input);

let hpargs = JSON.parse(input);

Object.keys(hpargs.usrfd).forEach(function (key, index) {
    let userfds = hpargs.usrfd[key];
    let userinput = fs.readFileSync(userfds[0], 'utf8');

    if (userinput.length > 0) {
        console.log("Input received from user " + key + ":");
        console.log(userinput);
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