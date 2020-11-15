const fs = require('fs');

const MAX_SEQ_PACKET_SIZE = 128 * 1024;

class HotPocketContract {

    init(executionCallback) {
        const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));

        const control = new ControlChannel(hpargs.hpfd);

        const pendingTasks = [];

        const executionContext = new ContractExecutionContext(hpargs, pendingTasks);
        invokeCallback(executionCallback, executionContext).then(() => {
            // Wait for any pending tasks added during execution.
            Promise.all(pendingTasks).then(() => {
                control.send("Terminated")
            });
        });
    }
}

class ContractExecutionContext {

    constructor(hpargs, pendingTasks) {
        this.readonly = hpargs.readonly;
        this.timestamp = hpargs.ts;
        this.users = new UsersCollection(hpargs.usrfd, pendingTasks);
        this.peers = new PeersCollection(hpargs.readonly, hpargs.unl, hpargs.nplfd)

        if (!hpargs.readonly) {
            const lclParts = hpargs.lcl.split("-");
            this.lcl = {
                seqNo: parseInt(lclParts[0]),
                hash: lclParts[1]
            };
        }
    }
}

class UsersCollection {

    #users = {};
    #totalUsers = 0;
    #pendingTasks = null

    constructor(usrfds, pendingTasks) {
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
        this.#pendingTasks = pendingTasks;
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

    onMessage(callback) {

        if (this.#totalUsers == 0)
            return Promise.resolve();

        // We create a promise which would get resolved when all users' message emissions have completed.
        const allUsersCompletedTask = new Promise(allUsersCompletionResolver => {

            let pendingUserCount = this.#totalUsers;
            const userMessageTasks = [];

            const onUserMessage = (user, msg) => {
                userMessageTasks.push(invokeCallback(callback, user, msg));
            };

            const onUserComplete = () => {
                pendingUserCount--;
                if (pendingUserCount == 0)
                    Promise.all(userMessageTasks).then(allUsersCompletionResolver)
            }

            Object.values(this.#users).forEach(u => {
                u.channel.consume((msg) => onUserMessage(u.user, msg), onUserComplete);
            })
        });

        // We add the all users completed task to the global pending tasks list so the contract execution will not
        // wrap up before this task is complete.
        this.#pendingTasks.push(allUsersCompletedTask);
        return allUsersCompletedTask;
    }
}

class User {
    pubKey = null;
    #channel = null;

    constructor(pubKey, channel) {
        this.pubKey = pubKey;
        this.#channel = channel;
    }

    async send(msg) {
        await this.#channel.send(msg);
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
        let remainingMsgCount = -1;
        let currentMsgLen = -1;
        let pos = 0;

        // Read bytes from the given buffer.
        const readBytes = (buf, pos, count) => {
            if (pos + count > buf.byteLength)
                return null;
            return buf.slice(pos, pos + count);
        }

        this.#readStream.on("data", (buf) => {
            pos = 0;
            if (remainingMsgCount == -1) {
                const msgCountBuf = readBytes(buf, 0, 4)
                remainingMsgCount = msgCountBuf.readUInt32BE();
                pos += 4;
            }

            while (pos < buf.byteLength) {
                if (currentMsgLen == -1) {
                    const msgLenBuf = readBytes(buf, pos, 4);
                    pos += 4;
                    currentMsgLen = msgLenBuf.readUInt32BE();
                }
                let possible_read_len;
                if (((buf.byteLength - pos) - currentMsgLen) >= 0) {
                    // Can finish reading a full message.
                    possible_read_len = currentMsgLen;
                    currentMsgLen = -1;
                } else {
                    // Only partial message is recieved.
                    possible_read_len = buf.byteLength - pos
                    currentMsgLen -= possible_read_len;
                }
                const msgBuf = readBytes(buf, pos, possible_read_len);
                pos += possible_read_len;
                dataParts.push(msgBuf)

                if (currentMsgLen == -1) {
                    onMessage(Buffer.concat(dataParts));
                    dataParts = [];
                    remainingMsgCount--
                }
            }

            if (remainingMsgCount == 0) {
                remainingMsgCount = -1;
                onComplete();
            }
        });
    }

    async send(msg) {
        const outputStringBuf = Buffer.from(msg);
        let headerBuf = Buffer.alloc(4);
        // Writing message length in big endian format.
        headerBuf.writeUInt32BE(outputStringBuf.byteLength)

        // We need to use synchronous writes (non-async) here because we want to atomically
        // write header and the message together without them getting rescheduled by NodeJs event loop.
        fs.writeSync(this.#fd, headerBuf);
        fs.writeSync(this.#fd, outputStringBuf);
    }
}

class PeersCollection {
    #peers = {};
    #channel = null;
    #readonly = false;
    #pendingTasks = null;

    constructor(readonly, unl, nplfd, pendingTasks) {
        this.#readonly = readonly;
        this.#pendingTasks = pendingTasks;

        if (!readonly) {
            unl.forEach(pubKey => {
                this.#peers[pubKey] = new Peer(pubKey);
            });

            this.#channel = new NplChannel(nplfd);
        }
    }

    onMessage(callback) {

        if (this.#readonly)
            throw "Peer messages not available in readonly mode.";

        this.#channel.consume((pubKey, msg) => {
            this.#pendingTasks.push(invokeCallback(callback, this.#peers[pubKey], msg));
        });
    }

    async send(msg) {
        if (this.#readonly)
            throw "Peer messages not available in readonly mode.";

        await this.#channel.send(msg);
    }
}

class Peer {
    pubKey = null;

    constructor(pubKey) {
        this.pubKey = pubKey;
    }
}

class NplChannel {

    #readStream = null;
    #fd = -1;

    constructor(fd) {
        this.#fd = fd;
    }

    consume(onMessage) {

        this.#readStream = fs.createReadStream(null, { fd: this.#fd, highWaterMark: MAX_SEQ_PACKET_SIZE });

        // From the hotpocket when sending the npl messages first it sends the pubkey of the particular node
        // and then the message, First data buffer is taken as pubkey and the second one as message,
        // then npl message object is constructed and the event is emmited.
        let pubKey = null;

        this.#readStream.on("data", (data) => {
            if (!pubKey) {
                pubKey = data.toString('hex');
            }
            else {
                onMessage(pubKey, data);
                pubKey = null;
            }
        });
    }

    send(msg) {
        return writeAsync(this.#fd, msg);
    }
}


class ControlChannel {

    #readStream = null;
    #fd = -1;

    constructor(fd) {
        this.#fd = fd;
    }

    consume(onMessage) {
        this.#readStream = fs.createReadStream(null, { fd: this.#fd, highWaterMark: MAX_SEQ_PACKET_SIZE });
        this.#readStream.on("data", onMessage);
    }

    send(msg) {
        return writeAsync(this.#fd, msg);
    }
}

const writeAsync = (fd, msg) => new Promise(resolve => {
    fs.write(fd, msg, resolve);
});

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