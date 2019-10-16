process.on('uncaughtException', (err) => {
    console.error('There was an uncaught error', err)
})
const fs = require('fs')
const pipe = require('posix-pipe-fork-exec')

let input = Buffer.from(pipe.getfdbytes(0)).toString()
console.log("===Sample contract started===");
console.log("Input received from hp: " + input);

let hpargs = JSON.parse(input);

Object.keys(hpargs.usrfd).forEach(function (key, index) {
    let userfds = hpargs.usrfd[key];
    let userinput = Buffer.from(pipe.getfdbytes(userfds[0])).toString().trim();

    if (userinput.length > 0) {
        console.log("Input received from user " + key + ":");
        console.log(userinput);
        fs.writeSync(userfds[1], "Echoing: " + userinput);
    }
});

console.log("===Sample contract ended===");