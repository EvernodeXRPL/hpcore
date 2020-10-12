const fs = require('fs');
const events = require('events');

MAX_NPL_BUF_SIZE = 128*1024;

function HotPocketContract() {
    const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
    this.readonly = hpargs.readonly;
    this.timestamp = hpargs.ts;

    if (!this.readonly) {
        const lclParts = hpargs.lcl.split("-");
        this.lcl = {
            seqNo: parseInt(lclParts[0]),
            hash: lclParts[1]
        };

        this.npl = new HotPocketNplChannel(hpargs.nplfd[0]);
    }

    this.users = {};
    Object.keys(hpargs.usrfd).forEach((userPubKey) => {
        const userfds = hpargs.usrfd[userPubKey];
        this.users[userPubKey] = new HotPocketChannel(userfds[0], userfds[1]);
    });
}

// Helper function to asynchronously read a stream to the end and fill a buffer.
const drainStream = function (stream) {

    return new Promise((resolve) => {

        const dataParts = [];

        const resolveBuffer = function () {
            if (dataParts.length > 0)
                return resolve(Buffer.concat(dataParts));
            else
                return resolve(null);
        }

        stream.on("data", d => {
            dataParts.push(d);
        });
        stream.on('end', resolveBuffer);
        stream.on("close", resolveBuffer);
        stream.on("error", () => {
            resolve(null);
        });
    });
}

function HotPocketChannel(infd, outfd) {
    this.readInput = function () {
        return new Promise((resolve) => {
            if (infd == -1) {
                resolve(null);
            }
            else {
                const s = fs.createReadStream(null, { fd: infd });
                drainStream(s).then(buf => resolve(buf));
            }
        });
    }

    this.sendOutput = function (output) {
        fs.writeFileSync(outfd, output);
    }
}

function HotPocketNplChannel(fd) {

    this.events = new events.EventEmitter();
    let socket = null;
    let isPubKeyReceived = false;
    let pubKey;
    if (fd > 0) {
        socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_NPL_BUF_SIZE});
        socket.on("data", d => {
            if (!isPubKeyReceived) {
                pubKey = d.toString('hex');
                isPubKeyReceived = true;
            }
            else {
                this.events.emit("message", {
                    pubkey: pubKey,
                    input: d.toString()
                });
                pubKey = null;
                isPubKeyReceived = false;
            }
        });
        socket.on("error", (e) => {
            this.events.emit("err", null);
        });
    }

    this.sendOutput = (output) => {
        if (fd > 0) {
            fs.writeSync(fd, output);
        }
    }

    this.closeNplChannel = () => {
        if (fd > 0) {
            socket.destroy();
        }
    }
}

module.exports = {
    HotPocketContract
}