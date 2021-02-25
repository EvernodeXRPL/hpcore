const fs = require('fs');
const tty = require('tty');
require('process');

const MAX_SEQ_PACKET_SIZE = 128 * 1024;
const controlMessages = {
    contractEnd: "contract_end",
    unlChangeset: "unl_changeset"
}
Object.freeze(controlMessages);

const clientProtocols = {
    json: "json",
    bson: "bson"
}
Object.freeze(clientProtocols);

const PATCH_CONFIG_PATH = "../patch.cfg";
const POST_EXEC_SCRIPT_NAME = "post_exec.sh";

class HotPocketContract {

    #controlChannel = null;
    #clientProtocol = null;

    init(contractFunc, clientProtocol = clientProtocols.json) {

        if (this.#controlChannel) // Already initialized.
            return false;

        this.#clientProtocol = clientProtocol;

        // Check whether we are running on a console and provide error.
        if (tty.isatty(process.stdin.fd)) {
            console.error("Error: Hot Pocket smart contracts must be executed via Hot Pocket.");
            return false;
        }

        // Parse HotPocket args.
        const argsJson = fs.readFileSync(process.stdin.fd, 'utf8');
        const hpargs = JSON.parse(argsJson);

        this.#controlChannel = new ControlChannel(hpargs.control_fd);
        this.#executeContract(hpargs, contractFunc);
        return true;
    }

    #executeContract = (hpargs, contractFunc) => {
        // Keeps track of all the tasks (promises) that must be awaited before the termination.
        const pendingTasks = [];
        const nplChannel = new NplChannel(hpargs.npl_fd);

        const users = new UsersCollection(hpargs.user_in_fd, hpargs.users, this.#clientProtocol);
        const unl = new UnlCollection(hpargs.readonly, hpargs.unl, nplChannel, pendingTasks);
        const executionContext = new ContractContext(hpargs, users, unl, this.#controlChannel);

        invokeCallback(contractFunc, executionContext).catch(errHandler).finally(() => {
            // Wait for any pending tasks added during execution.
            Promise.all(pendingTasks).catch(errHandler).finally(() => {
                nplChannel.close();
                this.#terminate();
            });
        });
    }

    #terminate = () => {
        this.#controlChannel.send({ type: controlMessages.contractEnd });
        this.#controlChannel.close();
    }
}

class ContractContext {

    #controlChannel = null;
    #patchConfig = null;

    constructor(hpargs, users, unl, controlChannel) {
        this.#controlChannel = controlChannel;
        this.readonly = hpargs.readonly;
        this.timestamp = hpargs.timestamp;
        this.users = users;
        this.unl = unl; // Not available in readonly mode.
        this.lcl_seq_no = hpargs.lcl_seq_no; // Not available in readonly mode.
        this.lcl_hash = hpargs.lcl_hash; // Not available in readonly mode.
        this.#patchConfig = new PatchConfig();
    }

    // Returns the config values in patch config.
    getConfig() {
        return this.#patchConfig.getConfig();
    }

    // Updates the config with given config object and save the patch config.
    updateConfig(config) {
        return this.#patchConfig.updateConfig(config);
    }
}

// Handles patch config manipulation.
class PatchConfig {

    // Loads the config value if there's a patch config file. Otherwise throw error.
    getConfig() {
        if (!fs.existsSync(PATCH_CONFIG_PATH))
            throw "Patch config file does not exist.";

        return new Promise((resolve, reject) => {
            fs.readFile(PATCH_CONFIG_PATH, 'utf8', function (err, data) {
                if (err) reject(err);
                else resolve(JSON.parse(data));
            });
        });
    }

    updateConfig(config) {

        this.validateConfig(config);

        return new Promise((resolve, reject) => {
            // Format json to match with the patch.cfg json format created by HP at the startup.
            fs.writeFile(PATCH_CONFIG_PATH, JSON.stringify(config, null, 4), (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    validateConfig(config) {
        // Validate all config fields.
        if (!config.version)
            throw "Contract version is not specified.";
        if (!config.unl || !config.unl.length)
            throw "UNL list cannot be empty.";
        for (let pubKey of config.unl) {
            // Pubkeys are validated against length, ed prefix and hex characters.
            if (!pubKey.length)
                throw "UNL pubKey not specified.";
            else if (!(/^(e|E)(d|D)[0-9a-fA-F]{64}$/g.test(pubKey)))
                throw "Invalid UNL pubKey specified.";
        }
        if (!config.bin_path || !config.bin_path.length)
            throw "Binary path cannot be empty.";
        if (config.roundtime <= 0)
            throw "Round time must be higher than zero."
        if (config.consensus != "public" && config.consensus != "private")
            throw "Invalid consensus flag configured in patch file. Valid values: public|private";
        if (config.npl != "public" && config.npl != "private")
            throw "Invalid npl flag configured in patch file. Valid values: public|private";
        if (config.round_limits.user_input_bytes < 0 || config.round_limits.user_output_bytes < 0 || config.round_limits.npl_output_bytes < 0 ||
            config.round_limits.proc_cpu_seconds < 0 || config.round_limits.proc_mem_bytes < 0 || config.round_limits.proc_ofd_count < 0)
            throw "Invalid round limits.";
        if (config.max_input_ledger_offset < 0)
            throw "Invalid max input ledger offset";
    }
}

class UsersCollection {

    #users = {};
    #infd = null;

    constructor(userInputsFd, usersObj, clientProtocol) {
        this.#infd = userInputsFd;

        Object.entries(usersObj).forEach(([pubKey, arr]) => {

            const outfd = arr[0]; // First array element is the output fd.
            arr.splice(0, 1); // Remove first element (output fd). The rest are pairs of msg offset/length tuples.

            const channel = new UserChannel(outfd, clientProtocol);
            this.#users[pubKey] = new User(pubKey, channel, arr);
        });
    }

    // Returns the User for the specified pubkey. Returns null if not found.
    find(pubKey) {
        return this.#users[pubKey]
    }

    // Returns all the currently connected users.
    list() {
        return Object.values(this.#users);
    }

    count() {
        return Object.keys(this.#users).length;
    }

    async read(input) {
        const [offset, size] = input;
        const buf = Buffer.alloc(size);
        await readAsync(this.#infd, buf, offset, size);
        return buf;
    }
}

class User {
    pubKey = null;
    inputs = null;
    #channel = null;

    constructor(pubKey, channel, inputs) {
        this.pubKey = pubKey;
        this.inputs = inputs;
        this.#channel = channel;
    }

    async send(msg) {
        await this.#channel.send(msg);
    }
}

class UserChannel {
    #outfd = -1;
    #clientProtocol = null;

    constructor(outfd, clientProtocol) {
        this.#outfd = outfd;
        this.#clientProtocol = clientProtocol;
    }

    send(msg) {
        const messageBuf = this.serialize(msg);
        let headerBuf = Buffer.alloc(4);
        // Writing message length in big endian format.
        headerBuf.writeUInt32BE(messageBuf.byteLength)
        return writevAsync(this.#outfd, [headerBuf, messageBuf]);
    }

    serialize(msg) {

        if (!msg)
            throw "Cannot serialize null content.";

        if (Buffer.isBuffer(msg))
            return msg;

        if (this.#clientProtocol == clientProtocols.bson) {
            return Buffer.from(msg);
        }
        else { // json

            // In JSON, we need to ensure that the final buffer contains a string.
            if (typeof msg === "string" || msg instanceof String)
                return Buffer.from(msg);
            else
                return Buffer.from(JSON.stringify(msg));
        }
    }
}

class UnlCollection {
    nodes = {};
    #channel = null;
    #readonly = false;
    #pendingTasks = null;

    constructor(readonly, unl, channel, pendingTasks) {
        this.#readonly = readonly;
        this.#pendingTasks = pendingTasks;

        if (!readonly) {
            unl.forEach(pubKey => {
                this.nodes[pubKey] = new UnlNode(pubKey);
            });

            this.#channel = channel;
        }
    }

    // Returns the unl node for the specified pubkey. Returns null if not found.
    find(pubKey) {
        return this.nodes[pubKey];
    }

    // Returns all the unl nodes.
    list() {
        return Object.values(this.nodes);
    }

    count() {
        return Object.keys(this.nodes).length;
    }

    // Registers for NPL messages.
    onMessage(callback) {

        if (this.#readonly)
            throw "NPL messages not available in readonly mode.";

        this.#channel.consume((pubKey, msg) => {
            this.#pendingTasks.push(invokeCallback(callback, this.nodes[pubKey], msg));
        });
    }

    // Broadcasts a message to all unl nodes (including self if self is part of unl).
    async send(msg) {
        if (this.#readonly)
            throw "NPL messages not available in readonly mode.";

        await this.#channel.send(msg);
    }
}

// Represents a node that's part of unl.
class UnlNode {
    pubKey = null;

    constructor(pubKey) {
        this.pubKey = pubKey;
    }
}

// Represents the node-party-line that can be used to communicate with unl nodes.
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
            throw ("NPL message exceeds max size " + MAX_SEQ_PACKET_SIZE);
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
const readAsync = (fd, buf, offset, size) => new Promise(resolve => fs.read(fd, buf, 0, size, offset, resolve));

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
    Contract: HotPocketContract,
    clientProtocols,
    POST_EXEC_SCRIPT_NAME,
}