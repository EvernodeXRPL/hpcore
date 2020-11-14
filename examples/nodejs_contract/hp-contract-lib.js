const fs = require('fs');

const MAX_SEQ_PACKET_SIZE = 128 * 1024;

class HotPocketContract {

    async init(executionCallback) {
        const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
        const control = new HotPocketControlChannel(hpargs.hpfd);

        const executionContext = new ContractExecutionContext(hpargs, control);
        await invokeCallback(executionCallback, executionContext);
        control.send("Terminated");
    }
}

class ContractExecutionContext {

    #npl = null;
    #hpargs = null;
    #control = null;

    constructor(hpargs, control) {
        this.#hpargs = hpargs;
        this.#control = control;
        this.readonly = hpargs.readonly;
        this.timestamp = hpargs.ts;
        this.unl = hpargs.unl;
        this.users = new UsersCollection(hpargs.usrfd);

        if (!this.readonly) {
            const lclParts = this.#hpargs.lcl.split("-");
            this.lcl = {
                seqNo: parseInt(lclParts[0]),
                hash: lclParts[1]
            };
        }
    }

    // init(eventRegistrationCallback) {

    //     eventRegistrationCallback(this.#events);

    //     if (!this.readonly)
    //         this.#npl = new NplChannel(this.#events, this.#hpargs.nplfd);
    // }

    sendNplMessage(msg) {
        //this.#npl && this.#npl.send(msg);
    }
}

class UsersCollection {

    #users = {};
    #totalUsers = 0;

    constructor(usrfds) {
        const userKeys = Object.keys(usrfds);

        userKeys.forEach((pubKey) => {
            const channel = new UserChannel(usrfds[pubKey]);
            const user = new User(pubKey, channel);
            this.#users[pubKey] = {
                user: user,
                channel: channel
            }
        });

        this.#totalUsers = userKeys.length;

    }

    get(pubKey) {
        const u = this.#users[pubKey];
        return u && u.user;
    }

    async forEach(callback) {
        Object.values(this.#users).forEach(async u => {
            await invokeCallback(callback, u.user);
        });
    }

    consumeMessages(onMessageCallback) {

        return new Promise(resolve => {

            if (this.#totalUsers == 0) {
                resolve();
            }
            else {
                let incompleteUserCount = this.#totalUsers;

                const onMessage = async (user, msg) => {
                    await invokeCallback(onMessageCallback, user, msg)
                };

                const onComplete = () => {
                    incompleteUserCount--;
                    if (incompleteUserCount == 0)
                        resolve();
                }

                Object.values(this.#users).forEach(u => {
                    u.channel.consume(async (msg) => await onMessage(u.user, msg), onComplete);
                })
            }
        })
    }
}

class User {
    pubKey = null;
    #channel = null;

    constructor(pubKey, channel) {
        this.pubKey = pubKey;
        this.#channel = channel;
    }

    send(msg) {
        this.#channel.send(msg);
    }
}

class UserChannel {
    #readStream = null;
    #fd = -1;

    constructor(fd) {
        this.#fd = fd;
    }

    consume(onMessage, onComplete) {

        this.#readStream = fs.createReadStream(null, { fd: this.#fd });
        let dataParts = [];
        let msgCount = -1;
        let msgLen = -1;
        let pos = 0;

        // Read bytes from the given buffer.
        const readBytes = (buf, pos, count) => {
            if (pos + count > buf.byteLength)
                return null;
            return buf.slice(pos, pos + count);
        }

        this.#readStream.on("data", async (buf) => {
            pos = 0;
            if (msgCount == -1) {
                const msgCountBuf = readBytes(buf, 0, 4)
                msgCount = msgCountBuf.readUInt32BE();
                pos += 4;
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
                    await invokeCallback(onMessage, Buffer.concat(dataParts));
                    dataParts = [];
                    msgCount--
                }
            }

            if (msgCount == 0) {
                msgCount = -1;
                await invokeCallback(onComplete);
            }
        });
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

class NplChannel {

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
                invokeCallback(callback, ...args);
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

const invokeCallback = async (callback, ...args) => {
    if (!callback)
        return;

    if (callback.constructor.name === 'AsyncFunction') {
        await callback(...args);
    }
    else {
        callback(...args);
    }
}

module.exports = {
    HotPocketContract
}