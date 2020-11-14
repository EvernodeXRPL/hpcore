const fs = require('fs');

const MAX_SEQ_PACKET_SIZE = 128 * 1024;

class HotPocketContract {

    #events = new AsyncCallbackEmitter();

    init(eventRegistrationCallback) {
        const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
        const control = new HotPocketControlChannel(hpargs.hpfd);

        eventRegistrationCallback(this.#events);

        const executionContext = new ContractExecutionContext(hpargs, control);
        this.#events.emit("exec", executionContext);
    }
}

class ContractExecutionContext {

    #events = new AsyncCallbackEmitter();
    #npl = null;
    #hpargs = null;
    #control = null;
    #incompleteUserCount = 0;
    users = {};

    #onUserComplete = () => {
        this.#incompleteUserCount--;
        if (this.#incompleteUserCount == 0) {
            events.emit("all_users_completed");
        }
    }

    constructor(hpargs, control) {
        this.#hpargs = hpargs;
        this.#control = control;
        this.readonly = hpargs.readonly;
        this.timestamp = hpargs.ts;
        this.unl = hpargs.unl;

        if (!this.readonly) {
            const lclParts = this.#hpargs.lcl.split("-");
            this.lcl = {
                seqNo: parseInt(lclParts[0]),
                hash: lclParts[1]
            };
        }
    }

    init(eventRegistrationCallback) {

        eventRegistrationCallback(this.#events);

        if (!this.readonly)
            this.#npl = new HotPocketNplChannel(this.#events, this.#hpargs.nplfd);

        const userKeys = Object.keys(this.#hpargs.usrfd);
        this.#incompleteUserCount = userKeys.length;
        userKeys.forEach((userPubKey) => {
            this.users[userPubKey] = new HotPocketUserChannel(this.#events, this.#hpargs.usrfd[userPubKey], userPubKey, this.#onUserComplete);
        });

        if (!Object.keys(this.#hpargs.usrfd).length) {
            this.#events.emit("all_users_completed");
        }
    }

    sendNplMessage(msg) {
        this.#npl && this.#npl.send(msg);
    }

    terminate() {
        this.#control.send("Terminated")
    }
}

class HotPocketUserChannel {
    #socket = null;
    #fd = -1;

    // Read bytes from the given buffer.
    #readBytes = (buf, pos, count) => {
        if (pos + count > buf.byteLength)
            return null;
        return buf.slice(pos, pos + count);
    }

    constructor(events, fd, userPubKey, onUserComplete) {
        if (fd <= 0)
            return;

        this.#socket = fs.createReadStream(null, { fd: fd });
        this.#fd = fd;
        let dataParts = [];
        let msgCount = -1;
        let msgLen = -1;
        let pos = 0;
        this.#socket.on("data", async (buf) => {
            pos = 0;
            if (msgCount == -1) {
                const msgCountBuf = this.#readBytes(buf, 0, 4)
                msgCount = msgCountBuf.readUInt32BE();
                pos += 4;
            }
            while (pos < buf.byteLength) {
                if (msgLen == -1) {
                    const msgLenBuf = this.#readBytes(buf, pos, 4);
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
                const msgBuf = this.#readBytes(buf, pos, possible_read_len);
                pos += possible_read_len;
                dataParts.push(msgBuf)

                if (msgLen == -1) {
                    await events.emit("user_message", userPubKey, Buffer.concat(dataParts));
                    dataParts = [];
                    msgCount--
                }
            }

            if (msgCount == 0) {
                msgCount = -1;
                events.emit("user_completed", userPubKey);
                onUserComplete();
            }
        });

        this.#socket.on("error", (e) => {
            events.emit("user_error", userPubKey, e);
        })
    }

    send(msg) {
        const outputStringBuf = Buffer.from(msg);
        let headerBuf = Buffer.alloc(4);
        // Writing message length in big endian format.
        headerBuf.writeUInt32BE(outputStringBuf.byteLength)
        fs.writeSync(this.#fd, headerBuf);
        fs.writeSync(this.#fd, outputStringBuf);
    }
}

class HotPocketNplChannel {

    #socket = null;
    #pubKey = null;
    #fd = null;

    constructor(events, fd) {

        if (fd > 0) {
            // From the hotpocket when sending the npl messages first it sends the pubkey of the particular node
            // and then the message, First data buffer is taken as pubkey and the second one as message,
            // then npl message object is constructed and the event is emmited.
            this.#socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_SEQ_PACKET_SIZE });
            this.#fd = fd;

            this.#socket.on("data", data => {
                if (!this.#pubKey) {
                    this.#pubKey = data.toString('hex');
                }
                else {
                    events.emit("npl_message", this.#pubKey, data);
                    this.#pubKey = null;
                }
            });
            this.#socket.on("error", (e) => {
                events.emit("npl_error", e);
            });
        }
    }

    send(msg) {
        if (this.#fd > 0) {
            fs.writeSync(this.#fd, msg);
        }
    }
}

class HotPocketControlChannel {

    events = new AsyncCallbackEmitter();
    #socket = null;
    #fd = null;

    constructor(fd) {
        if (fd > 0) {
            this.#socket = fs.createReadStream(null, { fd: fd, highWaterMark: MAX_SEQ_PACKET_SIZE });
            this.#fd = fd;

            this.#socket.on("data", d => {
                this.events.emit("control_message", d);
            });

            this.#socket.on("error", (e) => {
                this.events.emit("control_error", e);
            });
        }
    }

    send(output) {
        if (this.#fd > 0) {
            fs.writeSync(this.#fd, output);
        }
    }
}

class AsyncCallbackEmitter {
    callbacks = {};

    on(event, callback) {
        if (!this.callbacks[event]) {
            this.callbacks[event] = [];
        }
        this.callbacks[event].push(callback);
    };

    async emit(event, ...args) {
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

    removeAllListeners() {
        this.callbacks = {};
    };

    removeListener(event) {
        delete this.callbacks[event];
    };
}

module.exports = {
    HotPocketContract
}