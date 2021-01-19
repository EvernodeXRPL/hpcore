(() => {

    // Whether we are in Browser or NodeJs.
    const isBrowser = !(typeof window === 'undefined');

    // In browser, avoid duplicate initializations.
    if (isBrowser && window.HotPocket)
        return;

    const supportedHpVersion = "0.0";
    const serverChallengeSize = 16;
    const outputValidationPassThreshold = 0.8;
    const connectionCheckIntervalMs = 1000;
    const recentActivityThresholdMs = 3000;

    // External dependency references.
    let WebSocket = null;
    let sodium = null;
    let bson = null;
    let blake3 = null;

    /*--- Included in public interface. ---*/
    const protocols = {
        json: "json",
        bson: "bson" // (Requires nodejs or browserified hp client library on Browser)
    }
    Object.freeze(protocols);

    /*--- Included in public interface. ---*/
    const events = {
        disconnect: "disconnect",
        contractOutput: "contractOutput",
        contractReadResponse: "contractReadResponse",
        connectionChange: "connectionChange",
        unlChange: "unlChange"
    }
    Object.freeze(events);

    /*--- Included in public interface. ---*/
    const generateKeys = async (privateKeyHex = null) => {

        await initSodium();

        if (!privateKeyHex) {
            const keys = sodium.crypto_sign_keypair();
            return {
                privateKey: keys.privateKey,
                publicKey: keys.publicKey
            }
        }
        else {
            const binPrivateKey = hexToUint8Array(privateKeyHex);
            return {
                privateKey: Uint8Array.from(binPrivateKey),
                publicKey: Uint8Array.from(binPrivateKey.slice(32))
            }
        }
    }

    /*--- Included in public interface. ---*/
    const createClient = async (servers, clientKeys, options) => {

        const defaultOptions = {
            contractId: null,
            contractVersion: null,
            trustedServerKeys: null,
            protocol: protocols.json,
            requiredConnectionCount: 1,
            connectionTimeoutMs: 5000
        };
        const opt = options ? { ...defaultOptions, ...options } : defaultOptions;

        if (!clientKeys)
            throw "clientKeys not specified.";
        if (opt.contractId == "")
            throw "contractId not specified. Specify null to bypass contract id validation.";
        if (opt.contractVersion == "")
            throw "contractVersion not specified. Specify null to bypass contract version validation.";
        if (!opt.protocol || (opt.protocol != protocols.json && opt.protocol != protocols.bson))
            throw "Valid protocol not specified.";
        if (!opt.requiredConnectionCount || opt.requiredConnectionCount == 0)
            throw "requiredConnectionCount must be greater than 0.";
        if (!opt.connectionTimeoutMs || opt.connectionTimeoutMs == 0)
            throw "Connection timeout must be greater than 0.";

        await initSodium();
        await initBlake3();
        initWebSocket();
        if (opt.protocol == protocols.bson)
            initBson();

        // Load servers and serverKeys to object keys to avoid duplicates.

        const serversLookup = {};
        servers && servers.forEach(s => {
            const url = s.trim();
            if (url.length > 0)
                serversLookup[url] = true
        });
        if (Object.keys(serversLookup).length == 0)
            throw "servers not specified.";
        if (opt.requiredConnectionCount > Object.keys(serversLookup).length)
            throw "requiredConnectionCount is higher than no. of servers.";

        let trustedKeysLookup = {};
        opt.trustedServerKeys && opt.trustedServerKeys.sort().forEach(k => {
            const key = k.trim();
            if (key.length > 0)
                trustedKeysLookup[key] = true
        });
        if (Object.keys(trustedKeysLookup).length == 0)
            trustedKeysLookup = null;

        return new HotPocketClient(opt.contractId, opt.contractVersion, clientKeys, serversLookup, trustedKeysLookup, opt.protocol, opt.requiredConnectionCount, opt.connectionTimeoutMs);
    }

    function HotPocketClient(contractId, contractVersion, clientKeys, serversLookup, trustedKeysLookup, protocol, requiredConnectionCount, connectionTimeoutMs) {

        let emitter = new EventEmitter();

        // The accessor function passed into connections to query latest trusted key list.
        // We update the returning key list whenever we get a unl update.
        const getTrustedKeys = () => trustedKeysLookup;

        // Whenever unl change is reported, update the trusted key list.
        emitter.on(events.unlChange, (unl) => {
            trustedKeysLookup = {};
            unl.sort().forEach(pubkey => trustedKeysLookup[pubkey] = true);
        })

        const nodes = Object.keys(serversLookup).map(s => {
            return {
                server: s, // Server address.
                connection: null, // Hot Pocket connection (if any).
                lastActivity: 0 // Last connection activity timestamp.
            }
        });

        let status = 0; //0:none, 1:connected, 2:closed

        // This will get fired whenever the required connection count gets fullfilled.
        let initialConnectSuccess = null;

        // Tracks when was the earliest time that we were missing some required connections.
        // 0 indicates we are no missing any connections.
        let connectionsMissingFrom = new Date().getTime();

        // Checks for missing connections and attempts to establish them.
        const reviewConnections = () => {

            if (status == 2)
                return;

            // Check for connection changes periodically.
            setTimeout(() => {
                reviewConnections();
            }, connectionCheckIntervalMs);

            // Check whether we have fullfilled all required connections.
            if (nodes.filter(n => n.connection && n.connection.isConnected()).length == requiredConnectionCount) {
                connectionsMissingFrom = 0;
                initialConnectSuccess && initialConnectSuccess(true);
                initialConnectSuccess = null;
                status = 1;
                return;
            }

            if (connectionsMissingFrom == 0) {
                // Reaching here means we moved from connections-fullfilled state to missing-connections state.
                connectionsMissingFrom = new Date().getTime();
            }
            else if ((new Date().getTime() - connectionsMissingFrom) > connectionTimeoutMs) {

                // This means we were not able to maintain required connection count for the entire timeout period.

                console.log("Missing-connections timeout reached.");

                // Close and cleanup all connections if we hit the timeout.
                this.close().then(() => {
                    if (initialConnectSuccess) {
                        initialConnectSuccess(false);
                        initialConnectSuccess = null;
                    }
                    else {
                        emitter && emitter.emit(events.disconnect);
                    }
                });
                return;
            }

            // Reaching here means we should attempt to establish more connections if we have available slots.
            let currentConnectionCount = nodes.filter(n => n.connection).length;
            if (currentConnectionCount == requiredConnectionCount)
                return;

            // Find out available slots.
            // Skip nodes that are already connected or is currently establishing connection.
            // Skip nodes that have recently shown some connection activity.
            // Give priority to nodes that have not shown any activity recently.
            const freeNodes = nodes.filter(n => !n.connection && (new Date().getTime() - n.lastActivity) > recentActivityThresholdMs);
            freeNodes.sort((a, b) => a.lastActivity - b.lastActivity); // Oldest activity comes first.

            while (currentConnectionCount < requiredConnectionCount && freeNodes.length > 0) {

                // Get the next available node.
                const n = freeNodes.shift();
                n.connection = new HotPocketConnection(contractId, contractVersion, clientKeys, n.server, getTrustedKeys, protocol, connectionTimeoutMs, emitter);
                n.lastActivity = new Date().getTime();

                n.connection.connect().then(success => {
                    if (!success)
                        n.connection = null;
                    else
                        emitter && emitter.emit(events.connectionChange, n.server, "add");
                });

                n.connection.onClose = () => {
                    n.connection = null;
                    emitter && emitter.emit(events.connectionChange, n.server, "remove");
                };

                currentConnectionCount++;
            }
        }

        this.connect = () => {

            if (status > 0)
                return;

            reviewConnections();
            return new Promise(resolve => {
                initialConnectSuccess = resolve;
            })
        }

        this.close = async () => {

            if (status == 2)
                return;

            status = 2;
            emitter.clear(events.connectionChange);
            emitter.clear(events.contractOutput);
            emitter.clear(events.contractReadResponse);

            // Close all nodes connections.
            await Promise.all(nodes.filter(n => n.connection).map(n => n.connection.close()));
            nodes.forEach(n => n.connection = null);
        }

        this.on = (event, listener) => {
            emitter.on(event, listener);
        }

        this.sendContractInput = async (input, nonce = null, maxLclOffset = null) => {
            if (status == 2)
                return;

            return await Promise.all(
                nodes.filter(n => n.connection && n.connection.isConnected())
                    .map(n => n.connection.sendContractInput(input, nonce, maxLclOffset)));
        }

        this.sendContractReadRequest = (request) => {
            if (status == 2)
                return;

            nodes.filter(n => n.connection && n.connection.isConnected()).forEach(n => {
                n.connection.sendContractReadRequest(request);
            });
        }
    }

    function HotPocketConnection(contractId, contractVersion, clientKeys, server, getTrustedKeys, protocol, connectionTimeoutMs, emitter) {

        // Create message helper with JSON protocol initially.
        // After challenge handshake, we will change this to use the protocol specified by user.
        const msgHelper = new MessageHelper(clientKeys, protocols.json);

        let connectionStatus = 0; // 0:none, 1:server challenge sent, 2:handshake complete.
        let serverChallenge = null; // The hex challenge we have issued to the server.
        let reportedContractId = null;
        let reportedContractVersion = null;
        let pubkey = false; // Pubkey hex (with prefix) of this connection.

        let ws = null;
        let handshakeTimer = null; // Timer to track connection handshake timeout.
        let handshakeResolver = null;
        let closeResolver = null;
        let statResponseResolvers = [];
        let contractInputResolvers = {};

        // Calcualtes the blake3 hash of all array items.
        const getHash = (arr) => {
            const hash = blake3.createHash();
            arr.forEach(item => hash.update(item));
            return new Uint8Array(hash.digest());
        }

        // Get root hash of the given merkle hash tree. (called recursively)
        // checkHashString specifies the hash that must be checked for existance.
        const getMerkleHash = (tree, checkHashString) => {

            const listToHash = []; // Collects elements to hash.
            let checkHashFound = false;

            for (let elem of tree) {

                if (Array.isArray(elem)) {
                    // If the 'elem' is an array we should find the root hash of the array.
                    // Call this func recursively. If checkHash already found, pass null.
                    const result = getMerkleHash(elem, checkHashFound ? null : checkHashString);
                    if (result[0] == true)
                        checkHashFound = true;

                    listToHash.push(result[1]);
                }
                else {
                    // 'elem' is a single hash value. We get the hash bytes depending on the data type.
                    // (json encoding will use hex string and bson will use buffer)
                    const hashBytes = isString(elem) ? hexToUint8Array(elem) : elem.buffer;
                    listToHash.push(hashBytes);

                    // If checkHash is specified, compare the hashes.
                    if (checkHashString && msgHelper.stringifyValue(hashBytes) == checkHashString)
                        checkHashFound = true;
                }
            }

            // Return a tuple of whether check hash was found and the root hash of the provided merkle tree.
            return [checkHashFound, getHash(listToHash)];
        }

        // Verifies whether the provided root hash has enough signatures from unl.
        const validateHashSignatures = (rootHash, signatures, unlKeysLookup) => {

            const totalUnl = Object.keys(unlKeysLookup).length;
            if (totalUnl == 0) {
                console.log("Cannot validate outputs with empty unl.");
                return false;
            }

            const passedKeys = {};

            // 'signatures' is an array of pairs of [pubkey, signature]
            for (pair of signatures) {
                const pubkeyHex = msgHelper.stringifyValue(pair[0]); // Gets the pubkey hex to use for unl lookup key.

                // Get the signature and issuer pubkey bytes based on the data type.
                // (json encoding will use hex string and bson will use buffer)
                const pubkey = isString(pair[0]) ? hexToUint8Array(pair[0].substring(2)) : pair[0].buffer.slice(1); // Skip prefix byte.
                const sig = isString(pair[1]) ? hexToUint8Array(pair[1]) : pair[1].buffer;

                // Check whether the pubkey is in unl and whether signature is valid.
                if (!passedKeys[pubkeyHex] && unlKeysLookup[pubkeyHex] && sodium.crypto_sign_verify_detached(sig, rootHash, pubkey))
                    passedKeys[pubkeyHex] = true;
            }

            // Check the percentage of unl keys that passed the signature check.
            const passed = Object.keys(passedKeys).length;
            return ((passed / totalUnl) >= outputValidationPassThreshold);
        }

        const validateOutput = (msg, trustedKeys) => {

            // Calculate combined output hash with user's pubkey.
            const outputHash = getHash([[0xED], clientKeys.publicKey, ...msgHelper.spreadArrayField(msg.outputs)]);

            const result = getMerkleHash(msg.hashes, msgHelper.stringifyValue(outputHash));
            if (result[0] == true) {
                const rootHash = result[1];

                // Verify the issued signatures against the root hash.
                return validateHashSignatures(rootHash, msg.unl_sig, trustedKeys);
            }

            return false;
        }

        const handshakeMessageHandler = (m) => {

            if (connectionStatus == 0 && m.type == "user_challenge" && m.hp_version && m.contract_id) {

                if (m.hp_version != supportedHpVersion) {
                    console.log(`Incompatible Hot Pocket server version. Expected:${supportedHpVersion} Got:${m.hp_version}`);
                    return false;
                }
                else if (!m.contract_id) {
                    console.log("Server did not specify contract id.");
                    return false;
                }
                else if (contractId && m.contract_id != contractId) {
                    console.log(`Contract id mismatch. Expected:${contractId} Got:${m.contract_id}`);
                    return false;
                }
                else if (!m.contract_version) {
                    console.log("Server did not specify contract version.");
                    return false;
                }
                else if (contractVersion && m.contract_version != contractVersion) {
                    console.log(`Contract version mismatch. Expected:${contractVersion} Got:${m.contract_version}`);
                    return false;
                }

                reportedContractId = m.contract_id;
                reportedContractVersion = m.contract_version;

                // Generate the challenge we are sending to server.
                serverChallenge = uint8ArrayToHex(sodium.randombytes_buf(serverChallengeSize));

                // Sign the challenge and send back the response
                const response = msgHelper.createUserChallengeResponse(m.challenge, serverChallenge, protocol);
                ws.send(msgHelper.serializeObject(response));

                connectionStatus = 1;
                return true;
            }
            else if (connectionStatus == 1 && serverChallenge && m.type == "server_challenge_response" && m.sig && m.pubkey) {

                // Verify server challenge response.
                const stringToVerify = serverChallenge + reportedContractId + reportedContractVersion;
                const serverPubkeyHex = m.pubkey.substring(2); // Skip 'ed' prefix;
                if (!sodium.crypto_sign_verify_detached(hexToUint8Array(m.sig), stringToVerify, hexToUint8Array(serverPubkeyHex))) {
                    console.log(`${server} challenge response verification failed.`);
                    return false;
                }

                clearTimeout(handshakeTimer); // Cancel the handshake timeout monitor.
                handshakeTimer = null;
                serverChallenge = null; // Clear the sent challenge as we no longer need it.
                msgHelper.useProtocol(protocol); // Here onwards, use the message protocol specified by user.
                pubkey = m.pubkey; // Set this connection's public key.
                connectionStatus = 2; // Handshake complete.

                // If we are still connected, report handshaking as successful.
                // (If websocket disconnects, handshakeResolver will be already null)
                handshakeResolver && handshakeResolver(true);
                console.log(`Connected to ${server}`);

                // If this is currently a trusted connection, notify unl update.
                const trustedKeys = getTrustedKeys();
                if (trustedKeys && trustedKeys[pubkey]) {
                    // Prepare sorted new unl lookup object for equality comparison.
                    const newUnl = {};
                    m.unl.sort().forEach(k => newUnl[k] = true);

                    // Only emit unl change event if the unl has really changed.
                    if (JSON.stringify(trustedKeys) != JSON.stringify(newUnl))
                        emitter && emitter.emit(events.unlChange, m.unl);
                }

                return true;
            }

            console.log(`${server} invalid message during handshake. Connection status:${connectionStatus}`);
            console.log(m);
            return false;
        }

        const contractMessageHandler = (m) => {

            if (m.type == "contract_read_response") {
                emitter && emitter.emit(events.contractReadResponse, msgHelper.deserializeOutput(m.content));
            }
            else if (m.type == "contract_input_status") {
                const sigKey = msgHelper.stringifyValue(m.input_sig);
                const resolver = contractInputResolvers[sigKey];
                if (resolver) {
                    if (m.status == "accepted")
                        resolver("ok");
                    else
                        resolver(m.reason);
                    delete contractInputResolvers[sigKey];
                }
            }
            else if (m.type == "contract_output") {
                if (emitter) {
                    // Validate outputs if trusted keys is not null. (null means bypass validation)
                    const trustedKeys = getTrustedKeys();
                    if (!trustedKeys || validateOutput(m, trustedKeys))
                        m.outputs.forEach(output => emitter.emit(events.contractOutput, msgHelper.deserializeOutput(output)));
                    else
                        console.log("Output validation failed.");
                }
            }
            else if (m.type == "stat_response") {
                statResponseResolvers.forEach(resolver => {
                    resolver({
                        lcl: m.lcl,
                        lclSeqNo: m.lcl_seqno
                    });
                })
                statResponseResolvers = [];
            }
            else if (m.type == "unl_change") {
                // UNL change announcement message is handled in this block.
                console.log("Received :", m.type);
                console.log(m.unl);
            }
            
            else {
                console.log("Received unrecognized contract message: type:" + m.type);
                return false;
            }

            return true;
        }

        const messageHandler = async (rcvd) => {

            const data = (connectionStatus < 2 || protocol == protocols.json) ?
                (isBrowser ? await rcvd.data.text() : rcvd.data) :
                (isBrowser ? await rcvd.data.arrayBuffer() : rcvd.data);

            try {
                m = msgHelper.deserializeMessage(data);
            }
            catch (e) {
                console.log(e);
                console.log("Exception deserializing: ");
                console.log(data || rcvd);

                // If we get invalid message during handshake, close the socket.
                if (connectionStatus < 2)
                    this.close();

                return;
            }

            let isValid = false;
            if (connectionStatus < 2)
                isValid = handshakeMessageHandler(m);
            else if (connectionStatus == 2)
                isValid = contractMessageHandler(m);

            if (!isValid) {
                // If we get invalid message during handshake, close the socket.
                if (connectionStatus < 2)
                    this.close();
            }
        }

        const openHandler = () => {
            ws.addEventListener("message", messageHandler);
            ws.addEventListener("close", closeHandler);

            handshakeTimer = setTimeout(() => {
                // If handshake does not complete within timeout, close the connection.
                this.close();
                handshakeTimer = null;
            }, connectionTimeoutMs);
        }

        const closeHandler = () => {

            if (closeResolver)
                console.log("Closing connection to " + server);
            else
                console.log("Disconnected from " + server);

            emitter = null;

            if (handshakeTimer)
                clearTimeout(handshakeTimer);

            // If there are any ongoing resolvers resolve them with error output.

            handshakeResolver && handshakeResolver(false);
            handshakeResolver = null;

            statResponseResolvers.forEach(resolver => resolver(null));
            statResponseResolvers = [];

            Object.values(contractInputResolvers).forEach(resolver => resolver(null));
            contractInputResolvers = {};

            this.onClose && this.onClose();
            closeResolver && closeResolver();
        }

        const errorHandler = (e) => {
            handshakeResolver && handshakeResolver(false);
        }

        this.isConnected = () => {
            return connectionStatus == 2;
        };

        this.connect = () => {
            console.log("Connecting to " + server);
            return new Promise(resolve => {

                ws = isBrowser ? new WebSocket(server) : new WebSocket(server, { rejectUnauthorized: false });
                handshakeResolver = resolve;
                ws.addEventListener("error", errorHandler);
                ws.addEventListener("open", openHandler);
            });
        }

        this.close = () => {
            if (ws.readyState == WebSocket.OPEN) {
                return new Promise(resolve => {
                    closeResolver = resolve;
                    ws.close();
                });
            }
            else {
                return Promise.resolve();
            }
        }

        this.getStatus = () => {

            if (connectionStatus != 2)
                return Promise.resolve(null);

            const p = new Promise(resolve => {
                statResponseResolvers.push(resolve);
            });

            // If this is the only awaiting stat request, then send an actual stat request.
            // Otherwise simply wait for the previously sent request.
            if (statResponseResolvers.length == 1) {
                const msg = msgHelper.createStatusRequest();
                ws.send(msgHelper.serializeObject(msg));
            }
            return p;
        }

        this.sendContractInput = async (input, nonce = null, maxLclOffset = null) => {

            if (connectionStatus != 2)
                return null;

            if (!maxLclOffset)
                maxLclOffset = 10;

            if (!nonce)
                nonce = (new Date()).getTime().toString();
            else
                nonce = nonce.toString();

            // Acquire the current lcl and add the specified offset.
            const stat = await this.getStatus();
            if (!stat)
                return new Promise(resolve => resolve("ledger_status_error"));
            const maxLclSeqNo = stat.lclSeqNo + maxLclOffset;

            const msg = msgHelper.createContractInput(input, nonce, maxLclSeqNo);
            const sigKey = msgHelper.stringifyValue(msg.sig);
            const p = new Promise(resolve => {
                contractInputResolvers[sigKey] = resolve;
            });

            ws.send(msgHelper.serializeObject(msg));
            return p;
        }

        this.sendContractReadRequest = (request) => {

            if (connectionStatus != 2)
                return;

            const msg = msgHelper.createReadRequest(request);
            ws.send(msgHelper.serializeObject(msg));
        }
    }

    function MessageHelper(keys, protocol) {

        this.useProtocol = (p) => {
            protocol = p;
        }

        this.binaryEncode = (data) => {
            return protocol == protocols.json ?
                uint8ArrayToHex(data) :
                (Buffer.isBuffer(data) ? data : Buffer.from(data));
        }

        this.serializeObject = (obj) => {
            return protocol == protocols.json ? JSON.stringify(obj) : bson.serialize(obj);
        }

        this.deserializeMessage = (m) => {
            return protocol == protocols.json ? JSON.parse(m) : bson.deserialize(m);
        }

        this.serializeInput = (input) => {
            return protocol == protocols.json ?
                (isString(input) ? input : input.toString()) :
                (Buffer.isBuffer(input) ? input : Buffer.from(input));
        }

        this.deserializeOutput = (content) => {
            return protocol == protocols.json ? content : content.buffer;
        }

        // Used for generating strings to hold values as js object keys.
        this.stringifyValue = (val) => {
            if (isString(val))
                return val;
            else if (val instanceof Uint8Array)
                return uint8ArrayToHex(val);
            else if (val.buffer) // BSON binary.
                return uint8ArrayToHex(new Uint8Array(val.buffer));
            else
                throw "Cannot stringify signature.";
        }

        // Spreads hex/binary item array.
        this.spreadArrayField = (outputs) => {
            return protocol == protocols.json ? outputs : outputs.map(o => o.buffer);
        }

        this.createUserChallengeResponse = (userChallenge, serverChallenge, msgProtocol) => {
            // For challenge response encoding Hot Pocket always uses json.
            // Challenge response will specify the protocol to use for contract messages.
            const sigBytes = sodium.crypto_sign_detached(userChallenge, keys.privateKey);

            return {
                type: "user_challenge_response",
                sig: this.binaryEncode(sigBytes),
                pubkey: "ed" + this.binaryEncode(keys.publicKey),
                server_challenge: serverChallenge,
                protocol: msgProtocol
            }
        }

        this.createContractInput = (input, nonce, maxLclSeqNo) => {

            if (input.length == 0)
                return null;

            const inpContainer = {
                input: this.serializeInput(input),
                nonce: nonce,
                max_lcl_seqno: maxLclSeqNo
            }

            const serlializedInpContainer = this.serializeObject(inpContainer);
            const sigBytes = sodium.crypto_sign_detached(serlializedInpContainer, keys.privateKey);

            const signedInpContainer = {
                type: "contract_input",
                input_container: serlializedInpContainer,
                sig: this.binaryEncode(sigBytes)
            }

            return signedInpContainer;
        }

        this.createReadRequest = (request) => {
            if (request.length == 0)
                return null;

            return {
                type: "contract_read_request",
                content: this.serializeInput(request)
            }
        }

        this.createStatusRequest = () => {
            return { type: "stat" };
        }
    }

    function hexToUint8Array(hexString) {
        return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    }

    function uint8ArrayToHex(bytes) {
        return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
    }

    function isString(obj) {
        return (typeof obj === "string" || obj instanceof String);
    }

    function EventEmitter() {
        const registrations = {};

        this.on = (eventName, listener) => {
            if (!registrations[eventName])
                registrations[eventName] = [];
            registrations[eventName].push(listener);
        }

        this.emit = (eventName, ...value) => {
            if (registrations[eventName])
                registrations[eventName].forEach(listener => listener(...value));
        }

        this.clear = (eventName) => {
            if (eventName)
                delete registrations[eventName]
            else
                Object.keys(registrations).forEach(k => delete registrations[k]);
        }
    }

    // Set sodium reference.
    async function initSodium() {
        if (sodium) { // If already set, do nothing.
            return;
        }
        else if (isBrowser && window.sodium) { // browser (if sodium already loaded)
            sodium = window.sodium;
        }
        else if (isBrowser && !window.sodium) { // If sodium not yet loaded in browser, wait for sodium ready.
            sodium = await new Promise(resolve => {
                window.sodium = {
                    onload: async (sodiumRef) => resolve(sodiumRef)
                }
            })
        }
        else if (!isBrowser) { // nodejs
            sodium = require('libsodium-wrappers');
            await sodium.ready;
        }

        if (!sodium)
            throw "Sodium reference not found. Please include sodium js lib in browser scripts.";
    }

    // Set bson reference.
    function initBson() {
        if (bson) // If already set, do nothing.
            return;
        else if (isBrowser && window.BSON) // browser
            bson = window.BSON;
        else if (!isBrowser) // nodejs
            bson = require('bson');

        if (!bson)
            throw "BSON reference not found.";
    }

    // Set WebSocket reference.
    function initWebSocket() {
        if (WebSocket) // If already set, do nothing.
            return;
        else if (isBrowser && window.WebSocket) // browser
            WebSocket = window.WebSocket;
        else if (!isBrowser) // nodejs
            WebSocket = require('ws');

        if (!WebSocket)
            throw "WebSocket reference not found.";
    }

    let blake3Resolver = null;
    // Set blake3 reference.
    async function initBlake3() {
        if (blake3) // If already set, do nothing.
            return;
        else if (isBrowser && window.blake3) // browser (if blake3 already loaded)
            blake3 = window.blake3;
        else if (isBrowser && !window.blake3) // If blake3 not yet loaded in browser, wait for it.
            blake3 = await new Promise(resolve => blake3Resolver = resolve);
        else if (!isBrowser) // nodejs
            blake3 = require('blake3');

        if (!blake3)
            throw "Blake3 reference not found.";
    }

    function setBlake3(blake3ref) {
        if (blake3Resolver) {
            blake3Resolver(blake3ref)
            blake3Resolver = null;
        }
        else {
            blake3 = blake3ref;
        }
    }

    if (isBrowser) {
        window.HotPocket = {
            generateKeys,
            createClient,
            events,
            protocols,
            setBlake3
        };
    }
    else {
        module.exports = {
            generateKeys,
            createClient,
            events,
            protocols
        };
    }
})();