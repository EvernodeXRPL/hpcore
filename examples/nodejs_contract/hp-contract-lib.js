const fs = require('fs');
const events = require('events');

MAX_NPL_BUF_SIZE = 128 * 1024;

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

        this.npl = new HotPocketNplChannel(hpargs.nplfd);
    }

    this.control = new HotPocketControlChannel(hpargs.hpfd);

    this.users = {};
    Object.keys(hpargs.usrfd).forEach((userPubKey) => {
        this.users[userPubKey] = new HotPocketChannel(hpargs.usrfd[userPubKey]);
    });
}

function HotPocketChannel(fd) {
    let socket = null;
    this.readInput = function () {
        return new Promise((resolve) => {
            if (fd == -1) {
                resolve(null);
            }
            else {
                socket = fs.createReadStream(null, { fd: fd, highWaterMark: 5 });
                const dataParts = [];
                let msgLen = -1;
                let bytesRead = 0;
                socket.on("data", (buf) => {
                    if (msgLen == -1) {
                        // First two bytes indicate the message len.
                        const msgLenBuf = readBytes(buf, 0, 2);
                        if (!msgLenBuf) {
                            resolve(null);
                        }
                        msgLen = msgLenBuf.readUInt16BE();
                        const msgBuf = readBytes(buf, 2, buf.byteLength - 2);
                        dataParts.push(msgBuf)
                        bytesRead = msgBuf.byteLength;
                    } else {
                        dataParts.push(buf);
                        bytesRead += buf.length;
                    }
                    if (bytesRead == msgLen) {
                        msgLen == -1;
                        resolve(Buffer.concat(dataParts));
                    }
                });

                socket.on("close", () => {
                    this.closeChannel()
                    resolve(null);
                });
                socket.on("error", () => {
                    resolve(null);
                })
            }
        });
    }

    // Read bytes from the given buffer.
    const readBytes = function (buf, pos, count) {	
        if (pos + count > buf.byteLength)	
            return null;	
        return buf.slice(pos, pos + count);	
    }

    this.sendOutput = function (output) {
        fs.writeFileSync(fd, output);
    }

    this.closeChannel = function () {
        if (fd > 0) {
            socket.destroy();
        }
    }
}

function HotPocketNplChannel(fd) {

    this.events = new events.EventEmitter();
    let socket = null;
    let isPubKeyReceived = false;
    let pubKey;
    if (fd > 0) {
        // From the hotpocket when sending the npl messages first it sends the pubkey of the particular node
        // and then the message, First data buffer is taken as pubkey and the second one as message,
        // then npl message object is constructed and the event is emmited.
        socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_NPL_BUF_SIZE });
        socket.on("data", d => {
            if (!isPubKeyReceived) {
                pubKey = d.toString('hex');
                isPubKeyReceived = true;
            }
            else {
                this.events.emit("message", {
                    pubkey: pubKey,
                    input: d
                });
                pubKey = null;
                isPubKeyReceived = false;
            }
        });
        socket.on("error", (e) => {
            this.events.emit("error", e);
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

function HotPocketControlChannel(fd) {

    this.events = new events.EventEmitter();
    let socket = null;
    if (fd > 0) {
        socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_NPL_BUF_SIZE });
        socket.on("data", d => {
            this.events.emit("message", d);
        });
         
        socket.on("error", (e) => {
            this.events.emit("error", e);
        });
    }

    this.sendOutput = (output) => {
        if (fd > 0) {
            fs.writeSync(fd, output);
        }
    }

    this.closeControlChannel = () => {
        if (fd > 0) {
            socket.destroy();
        }
    }
}

module.exports = {
    HotPocketContract
}