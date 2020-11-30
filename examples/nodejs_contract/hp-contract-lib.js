const { EventEmitter } = require('events');
const fs = require('fs');

const MAX_SEQ_PACKET_SIZE = 128 * 1024;
const CONTROL_MESSAGE = {
    CONTRACT_END: "contract_end",
    UNL_CHANGESET: "unl_changeset"
}
Object.freeze(CONTROL_MESSAGE);

class HotPocketContract {

    events = new EventEmitter();
    #controlChannel = null;

    init(contractFunc) {

        if (this.#controlChannel) // Already initialized.
            return;

        // Parse HotPocket args.
        const argsJson = fs.readFileSync(0, 'utf8');
        const hpargs = JSON.parse(argsJson);

        this.#controlChannel = new ControlChannel(hpargs.controlfd);
        this.#executeContract(hpargs, contractFunc);
    }

    #executeContract = (hpargs, contractFunc) => {
        // Keeps track of all the tasks (promises) that must be awaited before the termination.
        const pendingTasks = [];

        const users = new UsersCollection(hpargs.userinfd, hpargs.users);
        const peers = new PeersCollection(hpargs.readonly, hpargs.unl, hpargs.nplfd, pendingTasks, this.events);
        const executionContext = new ContractExecutionContext(hpargs, users, peers, this.#controlChannel);

        this.events.emit("session_start");
        invokeCallback(contractFunc, executionContext).catch(errHandler).finally(() => {
            // Wait for any pending tasks added during execution.
            Promise.all(pendingTasks).catch(errHandler).finally(() => {
                this.events.emit("session_end");
                this.#terminate();
            });
        });
    }

    #terminate = () => {
        this.#controlChannel.send({ type: CONTROL_MESSAGE.CONTRACT_END });
        this.#controlChannel.close();
    }
}

class ContractExecutionContext {

    #controlChannel = null;

    constructor(hpargs, users, peers, controlChannel) {
        this.#controlChannel = controlChannel;
        this.readonly = hpargs.readonly;
        this.timestamp = hpargs.ts;
        this.users = users;
        this.peers = peers; // Not available in readonly mode.
        this.lcl = hpargs.lcl; // Not available in readonly mode.
    }

    async updateUnl(addArray, removeArray) {
        if (this.readonly)
            throw "UNL update not allowed in readonly mode."
        await this.#controlChannel.send({ type: CONTROL_MESSAGE.UNL_CHANGESET, add: addArray, remove: removeArray });
    }
}

class UsersCollection {

    #users = {};
    #totalUsers = 0;

    constructor(userInputsFd, usersObj) {
        const users = Object.entries(usersObj);

        users.forEach(([pubKey, arr]) => {

            const outfd = arr[0]; // First array element is the output fd.
            arr.splice(0, 1); // Remove first element (output fd). The rest are pairs of msg offset/length tuples.

            const channel = new UserChannel(userInputsFd, outfd, arr);
            const user = new User(pubKey, channel);

            this.#users[pubKey] = {
                user: user,
                channel: channel
            }
        });

        this.#totalUsers = users.length;
    }

    // Returns the User for the specified pubkey. Returns null if not found.
    find(pubKey) {
        const u = this.#users[pubKey];
        return u && u.user;
    }

    // Returns all the currently connected users.
    get() {
        return Object.values(this.#users).map(u => u.user);
    }

    count() {
        return Object.keys(this.#users).length;
    }

    async onMessage(callback) {

        if (this.#totalUsers == 0) {
            await Promise.resolve();
            return;
        }

        // We create a promise which would get resolved when all users' message handling have completed.
        const allUsersCompletedTask = new Promise(resolve => {

            let pendingUserCount = this.#totalUsers;
            const userMessageTasks = [];

            const onUserMessage = (user, msg) => {
                userMessageTasks.push(invokeCallback(callback, user, msg));
            };

            const onUserComplete = () => {
                pendingUserCount--;
                if (pendingUserCount == 0) {
                    // All user message events has been emitted.
                    // Now start waiting for queued up user message callback completion.
                    Promise.all(userMessageTasks).catch(errHandler).finally(resolve);
                }
            }

            // Register callback to consume all users messages.
            Object.values(this.#users).forEach(u => {
                u.channel.consume((msg) => onUserMessage(u.user, msg), onUserComplete);
            })
        });

        await allUsersCompletedTask;
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
    #infd = -1;
    #outfd = -1;
    #inputs = null;

    constructor(infd, outfd, inputs) {
        this.#infd = infd;
        this.#outfd = outfd;
        this.#inputs = inputs;
    }

    consume(onMessage, onComplete) {

        // Each input is 2 element array of [offset, length].
        for (const [offset, size] of this.#inputs) {
            const buf = Buffer.alloc(size);
            fs.readSync(this.#infd, buf, 0, size, offset);
            onMessage(buf);
        }

        onComplete();
    }

    send(msg) {
        const messageBuf = Buffer.from(msg);
        let headerBuf = Buffer.alloc(4);
        // Writing message length in big endian format.
        headerBuf.writeUInt32BE(messageBuf.byteLength)
        return writevAsync(this.#outfd, [headerBuf, messageBuf]);
    }
}

class PeersCollection {
    #peers = {};
    #channel = null;
    #readonly = false;
    #pendingTasks = null;

    constructor(readonly, unl, nplfd, pendingTasks, events) {
        this.#readonly = readonly;
        this.#pendingTasks = pendingTasks;

        if (!readonly) {
            unl.forEach(pubKey => {
                this.#peers[pubKey] = new Peer(pubKey);
            });

            this.#channel = new NplChannel(nplfd);
            events.on("session_end", () => this.#channel.close());
        }
    }

    // Returns the Peer for the specified pubkey. Returns null if not found.
    find(pubKey) {
        return this.#peers[pubKey];
    }

    // Returns all the peers.
    get() {
        return Object.values(this.#peers);
    }

    count() {
        return Object.keys(this.#peers).length;
    }

    // Registers for peer messages.
    onMessage(callback) {

        if (this.#readonly)
            throw "Peer messages not available in readonly mode.";

        this.#channel.consume((pubKey, msg) => {
            this.#pendingTasks.push(invokeCallback(callback, this.#peers[pubKey], msg));
        });
    }

    // Broadcasts a message to all peers (including self).
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
                pubKey = data.toString();
            }
            else {
                onMessage(pubKey, data);
                pubKey = null;
            }
        });

        this.#readStream.on("error", (err) => { });
    }

    send(msg) {
        const buf = Buffer.from(msg);
        if (buf.length > MAX_SEQ_PACKET_SIZE)
            throw ("Peer message exceeds max size " + MAX_SEQ_PACKET_SIZE);
        return writeAsync(this.#fd, buf);
    }

    close() {
        this.#readStream && this.#readStream.close();
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
        this.#readStream.on("error", (err) => { });
    }

    send(obj) {
        const buf = Buffer.from(JSON.stringify(obj));
        if (buf.length > MAX_SEQ_PACKET_SIZE)
            throw ("Control message exceeds max size " + MAX_SEQ_PACKET_SIZE);
        return writeAsync(this.#fd, buf);
    }

    close() {
        this.#readStream && this.#readStream.close();
    }
}

const writeAsync = (fd, buf) => new Promise(resolve => fs.write(fd, buf, resolve));
const writevAsync = (fd, bufList) => new Promise(resolve => fs.writev(fd, bufList, resolve));

const invokeCallback = async (callback, ...args) => {
    if (!callback)
        return;

    if (callback.constructor.name === 'AsyncFunction') {
        await callback(...args).catch(errHandler);
    }
    else {
        callback(...args);
    }
}

const errHandler = (err) => console.log(err);

module.exports = {
    HotPocketContract
}