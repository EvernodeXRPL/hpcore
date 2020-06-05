process.on('uncaughtException', (err) => {
    console.error('There was an uncaught error', err)
})
const fs = require('fs')

//console.log("===File contract started===");
//console.log("Contract args received from hp: " + input);

let hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));

// We just save execution args as an example state file change.
fs.appendFileSync("exects.txt", "ts:" + hpargs.ts + "\n");

Object.keys(hpargs.usrfd).forEach(function (key, index) {
    let userfds = hpargs.usrfd[key];

    if (userfds[0] != -1) {

        let fileContent = fs.readFileSync(userfds[0]);

        // Save the content into a new file.
        var fileName = new Date().getTime().toString();
        fs.writeFileSync(fileName, fileContent);
        fs.writeSync(userfds[1], "Saved file (len: " + fileContent.length / 1024 + " KB)");
    }
});

//console.log("===File contract ended===");