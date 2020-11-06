const fs = require('fs');

const MAX_SEQ_PACKET_SIZE = 128 * 1024;

function AsyncCallbackEmitter() {
    this.callbacks = {};

    this.on = (event, callback) => {
        if (!this.callbacks[event]) {
            this.callbacks[event] = [];
        }
        this.callbacks[event].push(callback);
    };

    this.emit = async (event, ...args) => {
        let eventCallbacks = this.callbacks[event];
        if (eventCallbacks && eventCallbacks.length) {
            await Promise.all(eventCallbacks.map(async callback => {
                if (callback.constructor.name === 'AsyncFunction') {
                    await callback(...args);
                }
                else {
                    callback(...args);
                }
            }));
        }
    };

    this.removeAllListeners = () => {
        this.callbacks = {};
    };

    this.removeListener = (event) => {
        delete this.callbacks[event];
    };
}

function HotPocketContract() {
    const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
    let autoCloseTimer = null;
    this.readonly = hpargs.readonly;
    this.timestamp = hpargs.ts;
    this.incompleteUsers = 0;

    if (!this.readonly) {
        const lclParts = hpargs.lcl.split("-");
        this.lcl = {
            seqNo: parseInt(lclParts[0]),
            hash: lclParts[1]
        };

        this.npl = new HotPocketNplChannel(hpargs.nplfd);
    }

    this.control = new HotPocketControlChannel(hpargs.hpfd);
    this.events = new AsyncCallbackEmitter();

    this.users = {};
    Object.keys(hpargs.usrfd).forEach((userPubKey) => {
        this.users[userPubKey] = new HotPocketChannel(this, hpargs.usrfd[userPubKey], userPubKey);
        this.incompleteUsers++;
    });

    this.terminate = () => {
        this.control.sendOutput("Terminated")
    }

    this.enableAutoClose = () => {
        if (!autoCloseTimer) {
            autoCloseTimer = setTimeout(() => {
                this.terminate();
            }, 1000);
        }
    }

    this.disableAutoClose = () => {
        if (autoCloseTimer) {
            clearTimeout(autoCloseTimer);
            autoCloseTimer = null;
        }
    }

    if (!Object.keys(hpargs.usrfd).length) {
        this.terminate();
    }
    else {
        this.enableAutoClose();
    }
}

function HotPocketChannel(contract, fd, userPubKey) {
    let socket = null;
    if (fd > 0) {
        socket = fs.createReadStream(null, { fd: fd });
        let dataParts = [];
        let msgCount = -1;
        let msgLen = -1;
        let pos = 0;
        socket.on("data", async (buf) => {
            pos = 0;
            if (msgCount == -1) {
                const msgCountBuf = readBytes(buf, 0, 4)
                msgCount = msgCountBuf.readUInt32BE();
                pos += 4;
                // disable auto close timer when start receiving messages.
                contract.disableAutoClose();
            }
            while (pos < buf.byteLength) {
                if (msgLen == -1) {
                    const msgLenBuf = readBytes(buf, pos, 4);
                    pos += 4;
                    msgLen = msgLenBuf.readUInt32BE();
                }
                let possible_read_len;
                if (((buf.byteLength - pos) - msgLen) >= 0) {
                    // Can finish reading a full message.
                    possible_read_len = msgLen;
                    msgLen = -1;
                } else {
                    // Only partial message is recieved.
                    possible_read_len = buf.byteLength - pos
                    msgLen -= possible_read_len;
                }
                const msgBuf = readBytes(buf, pos, possible_read_len);
                pos += possible_read_len;
                dataParts.push(msgBuf)

                if (msgLen == -1) {
                    await contract.events.emit("user_message", userPubKey, Buffer.concat(dataParts));
                    dataParts = [];
                    msgCount--
                }
                if (msgCount == 0) {
                    msgCount = -1
                    contract.incompleteUsers--;
                    if (contract.incompleteUsers == 0) {
                        contract.events.emit("all_users_completed");
                    }
                    else {
                        contract.enableAutoClose()
                    }
                    contract.events.emit("user_completed", userPubKey);
                }
            }
        });

        socket.on("error", (e) => {
            contract.events.emit("user_error", userPubKey, e);
        })
    }

    // Read bytes from the given buffer.
    const readBytes = function (buf, pos, count) {
        if (pos + count > buf.byteLength)
            return null;
        return buf.slice(pos, pos + count);
    }

    this.sendOutput = function (output) {
        const outputStringBuf = Buffer.from(output);
        let headerBuf = Buffer.alloc(4);
        // Writing message length in big endian format.
        headerBuf.writeUInt32BE(outputStringBuf.byteLength)
        fs.writeSync(fd, headerBuf);
        fs.writeSync(fd, outputStringBuf);
    }

    this.closeChannel = function () {
        if (fd > 0) {
            socket.destroy();
        }
    }
}

function HotPocketNplChannel(fd) {

    this.events = new AsyncCallbackEmitter();
    let socket = null;
    let isPubKeyReceived = false;
    let pubKey;
    if (fd > 0) {
        // From the hotpocket when sending the npl messages first it sends the pubkey of the particular node
        // and then the message, First data buffer is taken as pubkey and the second one as message,
        // then npl message object is constructed and the event is emmited.
        socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_SEQ_PACKET_SIZE });
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

    this.events = new AsyncCallbackEmitter();
    let socket = null;
    if (fd > 0) {
        socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_SEQ_PACKET_SIZE });
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