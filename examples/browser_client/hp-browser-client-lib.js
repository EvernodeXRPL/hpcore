window.HotPocket = (() => {

    const supported_hp_version = "0.0";
    const server_challenge_size = 16;

    const protocols = {
        json: "json"
    }
    Object.freeze(protocols);

    const events = {
        disconnect: "disconnect",
        contractOutput: "contractOutput",
        contractReadResponse: "contractReadResponse"
    }
    Object.freeze(events);

    function HotPocketClient(contractId, clientKeys, servers, validServerKeys, requiredConnectionCount = 1, connectionTimeoutMs = 5000) {

        if (!contractId || contractId == "")
            throw "contractId not spefified.";
        else if (!clientKeys)
            throw "clientKeys not specified.";
        else if (!validServerKeys || validServerKeys.length == 0)
            throw "validServerKeys not specified.";
        else if (!servers || servers.length == 0)
            throw "Servers not specified.";
        else if (requiredConnectionCount > servers)
            throw "connectionCount is higher than servers";

        const protocol = protocols.json;
        const nodes = servers.map(s => {
            return {
                server: s, // Server address.
                connection: null // Hot Pocket connection (if any).
            }
        });

        let currentConnectionCount = 0;

        // This will get fired whenever the required connection count gets fullfilled.
        let connectionFullfilledResolver = null;

        // Tracks when was the earliest time that we were missing some required connections.
        // 0 indicates we are no missing any connections.
        let connectionsMissingFrom = new Date().getTime();

        const reviewConnections = () => {
            if (requiredConnectionCount == currentConnectionCount) {
                connectionsMissingFrom = 0;
                connectionFullfilledResolver && connectionFullfilledResolver(true);
                return;
            }

            if (connectionsMissingFrom == 0) {
                connectionsMissingFrom = new Date().getTime();
            }
            else if ((new Date().getTime() - connectionsMissingFrom) > connectionTimeoutMs) {
                // Close and cleanup all connections if we hit the timeout.
                this.close().then(() => {
                    connectionFullfilledResolver && connectionFullfilledResolver(false);
                })
                return;
            }

            // Reaching here means we should attempt to establish more connections if we have available slots.

            // required connections minus no. of connections that are active or being established.
            const missingSlots = requiredConnectionCount - nodes.filter(n => n.connection).length;

            for (let i = 0; i < missingSlots; i++) {
                const n = nodes.find(n => !n.connection);
                if (!n)
                    break; // Break if no more empty slots.

                n.connection = new HotPocketConnection(contractId, clientKeys, n.server, validServerKeys, protocol, connectionTimeoutMs);

                n.connection.connect().then(success => {
                    if (success)
                        currentConnectionCount++;
                    else
                        n.connection = null;

                    //reviewConnections();
                });

                n.connection.on(events.disconnect, () => {
                    currentConnectionCount--;
                    //reviewConnections();
                });
            }
        }

        this.connect = () => {
            reviewConnections();
            return new Promise(resolve => {
                connectionFullfilledResolver = resolve;
            })
        }

        this.close = async () => {
            // Close all nodes connections.
            await Promise.all(nodes.filter(n => n.connection).map(n => n.connection.close()))
            nodes.forEach(n => n.connection = null);
        }
    }

    const KeyGenerator = {
        generate: function (privateKeyHex = null) {

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

    function HotPocketConnection(contractId, clientKeys, server, validServerKeys, protocol, connectionTimeoutMs) {
        const msgHelper = new MessageHelper(clientKeys, protocol);
        const emitter = new EventEmitter();

        let connectionStatus = 0; // 0:none, 1:server challenge sent, 2:handshake compelete
        let serverChallenge = null; // The hex challenge we have issued to the server.

        let ws = null;
        let isVoluntaryClose = false; // Indicates whether the web socket is being closed by ourselves.
        let handshakeTimer = null; // Timer to track connection handshake timeout.
        let handshakeResolver = null;
        let statResponseResolvers = [];
        let contractInputResolvers = {};

        const handshakeMessageHandler = (m) => {

            if (connectionStatus == 0 && m.type == 'user_challenge' && m.hp_version && m.contract_id) {

                if (m.hp_version != supported_hp_version) {
                    console.log("Incompatible Hot Pocket server version.");
                    return false;
                }

                if (m.contract_id != contractId) {
                    console.log("Contract id mismatch.");
                    return false;
                }

                // Generate the challenge we are sending to server.
                serverChallenge = toHexString(sodium.randombytes_buf(server_challenge_size));

                // Sign the challenge and send back the response
                const response = msgHelper.createUserChallengeResponse(m.challenge, serverChallenge);
                ws.send(msgHelper.serializeObject(response));

                connectionStatus = 1;
                return true;
            }
            else if (connectionStatus == 1 && serverChallenge && m.type == 'server_challenge_response' && m.sig && m.pubkey) {

                if (!validServerKeys.find(k => k == m.pubkey)) {
                    console.log("Server key not among the valid keys.");
                    return false;
                }

                // Verify server challenge response.
                const stringToVerify = serverChallenge + contractId;
                const serverPubkeyHex = m.pubkey.substring(2); // Skip 'ed' prefix;
                if (!sodium.crypto_sign_verify_detached(fromHexString(m.sig), stringToVerify, fromHexString(serverPubkeyHex))) {
                    console.log("Server challenge response verification failed.");
                    return false;
                }

                clearTimeout(handshakeTimer); // Cancel the handshake timeout monitor.
                serverChallenge = null; // Clear the sent challenge as we no longer need it.
                connectionStatus = 2; // Handshake complete.

                // If we are still connected, report handshaking as successful.
                // (If websocket disconnects, handshakeResolver will be already null)
                handshakeResolver && handshakeResolver(true);
                return true;
            }

            console.log("Invalid message during handshake");
            return false;
        }

        const contractMessageHandler = (m) => {

            if (m.type == 'contract_read_response') {
                emitter.emit(events.contractReadResponse, msgHelper.deserializeOutput(m.content));
            }
            else if (m.type == 'contract_input_status') {
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
            else if (m.type == 'contract_output') {
                emitter.emit(events.contractOutput, msgHelper.deserializeOutput(m.content));
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
                console.log("Received unrecognized message: type:" + m.type);
                return false;
            }

            return true;
        }

        const messageHandler = async (rcvd) => {

            let data = null;

            try {
                data = await rcvd.data.text();
                m = msgHelper.deserializeMessage(data);
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
                console.log("Invalid message. Connection status: " + connectionStatus);
                console.log(m);

                // If we get invalid message during handshake, close the socket.
                if (connectionStatus < 2)
                    this.close();
            }
        }

        const closeHandler = () => {
            // If there are any ongoing resolvers resolve them with error output.

            handshakeResolver && handshakeResolver(false);
            handshakeResolver = null;

            statResponseResolvers.forEach(resolver => resolver(null));
            statResponseResolvers = [];

            Object.values(contractInputResolvers).forEach(resolver => resolver(null));
            contractInputResolvers = {};

            // Fire the disconnect even if this is an abrupt closure.
            if (!isVoluntaryClose)
                emitter.emit(events.disconnect);
        }

        this.on = (event, listener) => {
            emitter.on(event, listener);
        }

        this.connect = () => {
            return new Promise(resolve => {
                handshakeResolver = resolve;
                ws = new WebSocket(server);
                ws.addEventListener("message", messageHandler);
                ws.addEventListener("close", closeHandler);

                handshakeTimer = setTimeout(() => {
                    // If handshake does not complete within timeout, close the connection.
                    this.close();
                }, connectionTimeoutMs);
            });
        }

        this.close = () => {
            isVoluntaryClose = true;
            return new Promise(resolve => {
                try {
                    ws.addEventListener("close", resolve);
                    ws.close();
                } catch (error) {
                    resolve();
                }
            })
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

        this.deserializeMessage = (m) => {
            return JSON.parse(m);
        }

        this.serializeInput = (input) => {
            return (typeof input === 'string' || input instanceof String) ? input : input.toString();
        }

        this.serializeSignature = (sig) => {
            return (typeof sig === 'string' || input instanceof String) ? sig : toHexString(sig);
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
            return { type: 'stat' };
        }
    }

    function fromHexString(hexString) {
        return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    }

    function toHexString(bytes) {
        return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
    }

    function EventEmitter() {
        const registrations = {};

        this.on = (eventName, listener) => {
            if (!registrations[eventName])
                registrations[eventName] = [];
            registrations[eventName].push(listener);
        }

        this.emit = (eventName, value) => {
            if (registrations[eventName])
                registrations[eventName].forEach(listener => listener(value));
        }
    }


    return {
        KeyGenerator: KeyGenerator,
        Client: HotPocketClient,
        events: events,
    }
})();