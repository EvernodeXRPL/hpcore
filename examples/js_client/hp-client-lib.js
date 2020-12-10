(() => {

    // Whether we are in Browser or NodeJs.
    const isBrowser = !(typeof window === 'undefined');

    if (isBrowser && window.HotPocket)
        return;

    const supportedHpVersion = "0.0";
    const serverChallengeSize = 16;
    const connectionCheckIntervalMs = 1000;
    const recentActivityThresholdMs = 3000;

    const protocols = {
        json: "json",
        bson: "bson" // Needs bson reference with initBson().
    }
    Object.freeze(protocols);

    const events = {
        disconnect: "disconnect",
        contractOutput: "contractOutput",
        contractReadResponse: "contractReadResponse",
        connectionChange: "connectionChange"
    }
    Object.freeze(events);

    let WebSocket = null;
    let sodium = null;
    let bson = null;

    function HotPocketClient(
        contractId, contractVersion, clientKeys, servers, serverKeys,
        protocol = protocols.json, requiredConnectionCount = 1, connectionTimeoutMs = 30000) {

        if (contractId == "")
            throw "contractId not specified. Specify null to bypass contract id validation.";
        if (contractVersion == "")
            throw "contractVersion not specified. Specify null to bypass contract version validation.";
        if (!clientKeys)
            throw "clientKeys not specified.";
        if (!protocol || (protocol != protocols.json && protocol != protocols.bson))
            throw "Valid protocol not specified.";
        if (!requiredConnectionCount || requiredConnectionCount == 0)
            throw "requiredConnectionCount must be greater than 0.";
        if (!connectionTimeoutMs || connectionTimeoutMs == 0)
            throw "Connection timeout must be greater than 0.";

        initWebSocket();
        initSodium();
        if (protocol == protocols.BSON)
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
        if (requiredConnectionCount > Object.keys(serversLookup).length)
            throw "requiredConnectionCount is higher than no. of servers.";

        let serverKeysLookup = null;
        if (serverKeys) {
            serverKeysLookup = {};
            serverKeys.forEach(k => {
                const key = k.trim();
                if (key.length > 0)
                    serverKeysLookup[key] = true
            });
        }
        if (serverKeysLookup && Object.keys(serverKeysLookup.length) == 0)
            throw "serverKeys must contain at least one key. Specify null to bypass key validation.";

        let emitter = new EventEmitter();

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
                n.connection = new HotPocketConnection(contractId, contractVersion, clientKeys, n.server, serverKeysLookup, protocol, connectionTimeoutMs, emitter);
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
            emitter = null;

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

            await Promise.all(
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

    const KeyGenerator = {
        generate: function (privateKeyHex = null) {

            initSodium();

            if (!privateKeyHex) {
                const keys = sodium.crypto_sign_keypair();
                return {
                    privateKey: keys.privateKey,
                    publicKey: keys.publicKey
                }
            }
            else {
                const binPrivateKey = fromHexString(privateKeyHex);
                return {
                    privateKey: Uint8Array.from(binPrivateKey),
                    publicKey: Uint8Array.from(binPrivateKey.slice(32))
                }
            }
        },
    }

    function HotPocketConnection(contractId, contractVersion, clientKeys, server, serverKeysLookup, protocol, connectionTimeoutMs, emitter) {
        const msgHelper = new MessageHelper(clientKeys, protocol);

        let connectionStatus = 0; // 0:none, 1:server challenge sent, 2:handshake complete.
        let serverChallenge = null; // The hex challenge we have issued to the server.
        let reportedContractId = null;
        let reportedContractVersion = null;

        let ws = null;
        let handshakeTimer = null; // Timer to track connection handshake timeout.
        let handshakeResolver = null;
        let closeResolver = null;
        let statResponseResolvers = [];
        let contractInputResolvers = {};

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
                serverChallenge = toHexString(sodium.randombytes_buf(serverChallengeSize));

                // Sign the challenge and send back the response
                const response = msgHelper.createUserChallengeResponse(m.challenge, serverChallenge);
                ws.send(msgHelper.serializeObject(response));

                connectionStatus = 1;
                return true;
            }
            else if (connectionStatus == 1 && serverChallenge && m.type == "server_challenge_response" && m.sig && m.pubkey) {

                // If server keys has been specified, validate whether this server's pubkey is among the valid list.
                if (serverKeysLookup && !serverKeysLookup[m.pubkey]) {
                    console.log(`${server} key '${m.pubkey}' not among the valid keys.`);
                    return false;
                }

                // Verify server challenge response.
                const stringToVerify = serverChallenge + reportedContractId + reportedContractVersion;
                const serverPubkeyHex = m.pubkey.substring(2); // Skip 'ed' prefix;
                if (!sodium.crypto_sign_verify_detached(fromHexString(m.sig), stringToVerify, fromHexString(serverPubkeyHex))) {
                    console.log(`${server} challenge response verification failed.`);
                    return false;
                }

                clearTimeout(handshakeTimer); // Cancel the handshake timeout monitor.
                handshakeTimer = null;
                serverChallenge = null; // Clear the sent challenge as we no longer need it.
                connectionStatus = 2; // Handshake complete.

                // If we are still connected, report handshaking as successful.
                // (If websocket disconnects, handshakeResolver will be already null)
                handshakeResolver && handshakeResolver(true);
                console.log(`Connected to ${server}`);
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
                const sigKey = msgHelper.serializeSignature(m.input_sig);
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
                emitter && emitter.emit(events.contractOutput, msgHelper.deserializeOutput(m.content));
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
                // During handshake stage, always using JSON format.
                m = msgHelper.deserializeMessage(data, (connectionStatus < 2 ? protocols.json : protocol));

            } catch (e) {
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
            return new Promise(resolve => {
                closeResolver = resolve;
                ws.close();
            });
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
            const sigKey = msgHelper.serializeSignature(msg.sig);
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

        this.binaryEncode = (data) => {
            return toHexString(data);
        }

        this.serializeObject = (obj) => {
            return JSON.stringify(obj);
        }

        this.deserializeMessage = (m, protocol = protocols.json) => {
            return JSON.parse(m);
        }

        this.serializeInput = (input) => {
            return (typeof input === "string" || input instanceof String) ? input : input.toString();
        }

        this.serializeSignature = (sig) => {
            return (typeof sig === "string" || input instanceof String) ? sig : toHexString(sig);
        }

        this.deserializeOutput = (content) => {
            return content;
        }

        this.createUserChallengeResponse = (userChallenge, serverChallenge) => {
            // For challenge response encoding Hot Pocket always uses json.
            // Challenge response will specify the protocol to use for contract messages.
            const sigBytes = sodium.crypto_sign_detached(userChallenge, keys.privateKey);

            return {
                type: "user_challenge_response",
                sig: toHexString(sigBytes),
                pubkey: "ed" + toHexString(keys.publicKey),
                server_challenge: serverChallenge,
                protocol: protocol
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

    function fromHexString(hexString) {
        return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    }

    function toHexString(bytes) {
        return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
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

        this.clear = () => {
            Object.keys(registrations).forEach(k => delete registrations[k]);
        }
    }

    // Set sodium reference.
    function initSodium(sodiumRef) {
        if (sodium) // If already set, do nothing.
            return;
        if (sodiumRef)
            sodium = sodiumRef;
        else if (isBrowser && window.sodium) // If no parameter specified, try to get from window.sodium.
            sodium = window.sodium;
        else
            throw "Sodium reference not set.";
    }

    // Set bson reference.
    function initBson() {
        if (bson) // If already set, do nothing.
            return;
        else if (bsonRef)
            bson = bsonRef;
        else if (isBrowser && window.BSON) // If no parameter specified, try to get from window.BSON.
            bson = window.BSON;
        else if (!isBrowser)
            bson = require('bson');
    }

    // Set WebSocket reference.
    function initWebSocket() {
        if (WebSocket) // If already set, do nothing.
            return;
        else if (isBrowser && window.WebSocket) // If no parameter specified, try to get from window.WebSocket.
            WebSocket = window.WebSocket;
        else if (!isBrowser)
            WebSocket = require('ws');
    }

    const hotPocketLib = {
        KeyGenerator: KeyGenerator,
        Client: HotPocketClient,
        events: events,
        protocols: protocols,
        initSodium: initSodium
    }

    if (isBrowser)
        window.HotPocket = hotPocketLib;
    else
        module.exports = hotPocketLib;
})();