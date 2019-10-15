process.on('uncaughtException', (err) => {
    console.error('There was an uncaught error', err)
})
const fs = require('fs')
const pipe = require('posix-pipe-fork-exec')

let input = Buffer.from(pipe.getfdbytes(0)).toString()
console.log("===Sample contract started===");
console.log(input)
console.log("===Sample contract ended===");