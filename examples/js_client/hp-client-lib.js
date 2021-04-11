(() => {

    // Whether we are in Browser or NodeJs.
    const isBrowser = !(typeof window === 'undefined');

    // In browser, avoid duplicate initializations.
    if (isBrowser && window.HotPocket)
        return;

    const supportedHpVersion = "1.0.0";
    const serverChallengeSize = 16;
    const outputValidationPassThreshold = 0.8;
    const connectionCheckIntervalMs = 1000;
    const recentActivityThresholdMs = 3000;
    const edKeyType = 237;
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();

    // External dependency references.
    let WebSocket = null;
    let sodium = null;
    let bson = null;
    let blake3 = null;
    let logLevel = 0; // 0=info, 1=error

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
    // privateKeyHex: Hex private key with prefix ('ed').
    // Returns 'ed' (237) prefixed binary public/private keys.
    const generateKeys = async (privateKeyHex = null) => {

        await initSodium();

        if (!privateKeyHex) {
            const keys = sodium.crypto_sign_keypair();

            const binPrivateKey = new Uint8Array(65);
            binPrivateKey[0] = edKeyType;
            binPrivateKey.set(keys.privateKey, 1);

            const binPublicKey = new Uint8Array(33);
            binPublicKey[0] = edKeyType;
            binPublicKey.set(keys.publicKey, 1);

            return {
                privateKey: binPrivateKey,
                publicKey: binPublicKey
            }
        }
        else {
            const binPrivateKey = hexToUint8Array(privateKeyHex);
            if (binPrivateKey[0] != edKeyType)
                throw "Invaid key type. 'ed' expected.";

            const binPublicKey = new Uint8Array(33);
            binPublicKey[0] = edKeyType;
            binPublicKey.set(binPrivateKey.slice(33), 1);
            return {
                privateKey: binPrivateKey,
                publicKey: binPublicKey
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
        // 0 indicates we are not missing any connections. This will be initially set when connect() is called.
        let connectionsMissingFrom = 0;

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

                liblog(1, "Missing-connections timeout reached.");

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

        /**
         * Executes the provided func on all connections and returns the collected results.
         * @param func The function taking a HP Connection as a parameter. This will get executed on all connections.
         * @param maxConnections Maximum no. of connections to use. Uses all available connections if null.
         */
        const getMultiConnectionResult = async (func, maxConnections) => {
            if (status == 2)
                return await Promise.resolve();

            if (maxConnections == null)
                maxConnections = requiredConnectionCount;

            const connections = nodes.filter(n => n.connection && n.connection.isConnected()).map(n => n.connection).slice(0, maxConnections);
            const results = await Promise.all(connections.map(c => func(c)));

            // If we are expecting only 1 connection, then return null or single result.
            // Otherwise return the array of results.
            if (maxConnections == 1 && results.length <= 1)
                return results.length == 0 ? null : results[0];
            else
                return results;
        }

        /**
         * Executes the provided func on all connections.
         * @param func The function taking a HP Connection as a parameter. This will get executed on all connections.
         * @param maxConnections Maximum no. of connections to use. Uses all available connections if null.
         */
        const executeMultiConnectionFunc = (func, maxConnections) => {

            if (status == 2)
                return Promise.resolve();

            if (maxConnections == null)
                maxConnections = requiredConnectionCount;

            const connections = nodes.filter(n => n.connection && n.connection.isConnected()).map(n => n.connection).slice(0, maxConnections);
            return Promise.all(connections.map(c => func(c)));
        }

        this.connect = () => {

            if (status > 0)
                return;

            // Start the missing-connections timer tracking from this point onwards.
            connectionsMissingFrom = new Date().getTime();
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

        this.clear = (event) => {
            emitter.clear(event);
        }

        this.submitContractInput = (input, nonce = null, maxLedger = null, isOffset = true) => {
            // We always only submit contract input to a single node (even if we are connected to multiple nodes).
            return getMultiConnectionResult(con => con.submitContractInput(input, nonce, maxLedger, isOffset), 1);
        }

        this.sendContractReadRequest = (request) => {
            return executeMultiConnectionFunc(con => con.sendContractReadRequest(request));
        }

        this.getStatus = () => {
            return getMultiConnectionResult(con => con.getStatus());
        }

        this.getLedgerBySeqNo = (seqNo, includeInputs, includeOutputs) => {
            return getMultiConnectionResult(con => con.getLedgerBySeqNo(seqNo, includeInputs, includeOutputs));
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
        let contractInputResolvers = {}; // Contract input status-awaiting resolvers (keyed by input hash).
        let ledgerQueryResolvers = {}; // Message resolvers that uses request/reply associations.

        // Calcualtes the blake3 hash of all array items.
        const getHash = (arr) => {
            const hash = blake3.createHash();
            arr.forEach(item => hash.update(item));
            return new Uint8Array(hash.digest());
        }

        // Get root hash of the given merkle hash tree. (called recursively)
        // Merkle hash tree indicates the collapsed output hashes of this round for all users.
        // This user's output hash is indicated in the tree as null.
        // selfHash: specifies the output hash of this user.
        const getMerkleHash = (tree, selfHash) => {

            const listToHash = []; // Collects elements to hash.
            let selfHashFound = false;

            for (let elem of tree) {

                if (Array.isArray(elem)) {
                    // If the 'elem' is an array we should find the root hash of the array.
                    // Call this func recursively. If self hash already found, pass null.
                    const result = getMerkleHash(elem, selfHashFound ? null : selfHash);
                    if (result[0] == true)
                        selfHashFound = true;

                    listToHash.push(result[1]);
                }
                else { // elem' is a single hash value
                    // We get the hash bytes depending on the data type. (json encoding will use hex string
                    // and bson will use buffer). If the elem contains null, that means it represents the
                    // self hash. So we should substitute the self hash to null.

                    // If we have already found self hash (indicated by selfHash=null), we cannot encounter
                    // null element again.
                    if (!selfHash && !elem) {
                        liblog(1, "Self hash encountered more than once in output hash tree.");
                        return [false, null];
                    }

                    if (!elem)
                        selfHashFound = true;

                    const hashBytes = elem ? msgHelper.binaryDecode(elem) : selfHash; // If element is null, use self hash.
                    listToHash.push(hashBytes);
                }
            }

            // Return a tuple of whether self hash was found and the root hash of the provided merkle tree.
            return [selfHashFound, getHash(listToHash)];
        }

        // Verifies whether the provided root hash has enough signatures from unl.
        const validateHashSignatures = (rootHash, signatures, unlKeysLookup) => {

            const totalUnl = Object.keys(unlKeysLookup).length;
            if (totalUnl == 0) {
                liblog(1, "Cannot validate outputs with empty unl.");
                return false;
            }

            const passedKeys = {};

            // 'signatures' is an array of pairs of [pubkey, signature]
            for (pair of signatures) {
                const pubkeyHex = msgHelper.stringifyValue(pair[0]); // Gets the pubkey hex to use for unl lookup key.

                // Get the signature and issuer pubkey bytes based on the data type.
                // (json encoding will use hex string and bson will use buffer)
                const binPubkey = msgHelper.binaryDecode(pair[0]);
                const sig = msgHelper.binaryDecode(pair[1]);

                // Check whether the pubkey is in unl and whether signature is valid.
                if (!passedKeys[pubkeyHex] && unlKeysLookup[pubkeyHex] && sodium.crypto_sign_verify_detached(sig, rootHash, binPubkey.slice(1)))
                    passedKeys[pubkeyHex] = true;
            }

            // Check the percentage of unl keys that passed the signature check.
            const passed = Object.keys(passedKeys).length;
            return ((passed / totalUnl) >= outputValidationPassThreshold);
        }

        const verifyContractOutputTrust = (msg, trustedKeys) => {

            // Calculate combined output hash with user's pubkey.
            const outputHash = getHash([clientKeys.publicKey, ...msgHelper.spreadArrayField(msg.outputs)]);

            // Check whether calculated output hash is same as output hash indicated in the message.
            if (!arraysEqual(outputHash, msgHelper.binaryDecode(msg.output_hash))) {
                liblog(1, "Contract output hash mismatch.");
                return false;
            }

            const hashResult = getMerkleHash(msg.hash_tree, outputHash);

            // hashResult is a tuple containing whether self hash was found and the calculated root hash of the merkle hash tree.
            if (hashResult[0] == true) {
                const rootHash = hashResult[1];

                // Verify the issued signatures against the root hash.
                return validateHashSignatures(rootHash, msg.unl_sig, trustedKeys);
            }

            return false;
        }

        const validateAndEmitUnlChange = (changedUnl) => {
            // If this is currently a trusted connection, notify unl update.
            const trustedKeys = getTrustedKeys();
            if (trustedKeys && trustedKeys[pubkey]) {
                // Prepare sorted new unl lookup object for equality comparison.
                const newUnl = {};
                changedUnl.sort().forEach(k => newUnl[k] = true);

                // Only emit unl change event if the unl has really changed.
                if (JSON.stringify(trustedKeys) != JSON.stringify(newUnl))
                    emitter && emitter.emit(events.unlChange, changedUnl);
            }
        }

        const handshakeMessageHandler = (m) => {

            if (connectionStatus == 0 && m.type == "user_challenge" && m.hp_version && m.contract_id) {

                if (m.hp_version != supportedHpVersion) {
                    liblog(1, `Incompatible Hot Pocket server version. Expected:${supportedHpVersion} Got:${m.hp_version}`);
                    return false;
                }
                else if (!m.contract_id) {
                    liblog(1, "Server did not specify contract id.");
                    return false;
                }
                else if (contractId && m.contract_id != contractId) {
                    liblog(1, `Contract id mismatch. Expected:${contractId} Got:${m.contract_id}`);
                    return false;
                }
                else if (!m.contract_version) {
                    liblog(1, "Server did not specify contract version.");
                    return false;
                }
                else if (contractVersion && m.contract_version != contractVersion) {
                    liblog(1, `Contract version mismatch. Expected:${contractVersion} Got:${m.contract_version}`);
                    return false;
                }

                reportedContractId = m.contract_id;
                reportedContractVersion = m.contract_version;

                // Generate the challenge we are sending to server.
                serverChallenge = uint8ArrayToHex(sodium.randombytes_buf(serverChallengeSize));

                // Sign the challenge and send back the response
                const response = msgHelper.createUserChallengeResponse(m.challenge, serverChallenge, protocol);
                wsSend(msgHelper.serializeObject(response));

                connectionStatus = 1;
                return true;
            }
            else if (connectionStatus == 1 && serverChallenge && m.type == "server_challenge_response" && m.sig && m.pubkey) {

                // Verify server challenge response.
                const stringToVerify = serverChallenge + reportedContractId + reportedContractVersion;
                const serverPubkeyHex = m.pubkey.substring(2); // Skip 'ed' prefix;
                if (!sodium.crypto_sign_verify_detached(hexToUint8Array(m.sig), stringToVerify, hexToUint8Array(serverPubkeyHex))) {
                    liblog(1, `${server} challenge response verification failed.`);
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
                liblog(0, `Connected to ${server}`);

                validateAndEmitUnlChange(m.unl);

                return true;
            }

            liblog(1, `${server} invalid message during handshake. Connection status:${connectionStatus}`);
            liblog(0, m);
            return false;
        }

        const contractMessageHandler = (m) => {

            if (m.type == "contract_read_response") {
                emitter && emitter.emit(events.contractReadResponse, msgHelper.deserializeValue(m.content));
            }
            else if (m.type == "contract_input_status") {
                const inputHashHex = msgHelper.stringifyValue(m.input_hash);
                const resolver = contractInputResolvers[inputHashHex];
                if (resolver) {
                    const result = { status: m.status }

                    if (m.status == "accepted") {
                        result.ledgerSeqNo = m.ledger_seq_no;
                        result.ledgerHash = msgHelper.deserializeValue(m.ledger_hash);
                    }
                    else {
                        result.reason = m.reason;
                    }

                    resolver(result);
                    delete contractInputResolvers[inputHashHex];
                }
            }
            else if (m.type == "contract_output") {
                if (emitter) {
                    // Validate outputs if trusted keys is not null. (null means bypass validation)
                    const trustedKeys = getTrustedKeys();

                    if (!trustedKeys || verifyContractOutputTrust(m, trustedKeys)) {
                        emitter.emit(events.contractOutput, {
                            ledgerSeqNo: m.ledger_seq_no,
                            ledgerHash: msgHelper.deserializeValue(m.ledger_hash),
                            outputHash: msgHelper.deserializeValue(m.output_hash),
                            outputs: m.outputs.map(o => msgHelper.deserializeValue(o))
                        });
                    }
                    else
                        liblog(1, "Output validation failed.");
                }
            }
            else if (m.type == "stat_response") {
                statResponseResolvers.forEach(resolver => {
                    resolver({
                        hpVersion: m.hp_version,
                        ledgerSeqNo: m.ledger_seq_no,
                        ledgerHash: msgHelper.deserializeValue(m.ledger_hash),
                        roundTime: m.round_time,
                        contractExecutionEnabled: m.contract_execution_enabled,
                        readRequestsEnabled: m.read_requests_enabled,
                        isFullHistoryNode: m.is_full_history_node,
                        currentUnl: m.current_unl,
                        peers: m.peers
                    });
                })
                statResponseResolvers = [];
            }
            else if (m.type == "unl_change") {
                if (m.unl) {
                    // Convert unl pubkeys to hex string.
                    let unl = m.unl.map(k => msgHelper.stringifyValue(k));
                    validateAndEmitUnlChange(unl);
                }
            }
            else if (m.type == "ledger_query_result") {
                const resolver = ledgerQueryResolvers[m.reply_for];
                if (resolver) {
                    const results = m.results.map(r => {
                        const result = {
                            seqNo: r.seq_no,
                            timestamp: r.timestamp,
                            hash: msgHelper.deserializeValue(r.hash),
                            prevHash: msgHelper.deserializeValue(r.prev_hash),
                            stateHash: msgHelper.deserializeValue(r.state_hash),
                            configHash: msgHelper.deserializeValue(r.config_hash),
                            userHash: msgHelper.deserializeValue(r.user_hash),
                            inputHash: msgHelper.deserializeValue(r.input_hash),
                            outputHash: msgHelper.deserializeValue(r.output_hash)
                        }

                        if (r.inputs) {
                            result.inputs = r.inputs.map(i => {
                                return {
                                    pubkey: msgHelper.deserializeValue(i.pubkey),
                                    hash: msgHelper.deserializeValue(i.hash),
                                    blob: msgHelper.deserializeValue(i.blob)
                                }
                            });
                        }

                        if (r.outputs) {
                            result.outputs = r.outputs.map(o => {
                                return {
                                    pubkey: msgHelper.deserializeValue(o.pubkey),
                                    hash: msgHelper.deserializeValue(o.hash),
                                    blobs: o.blobs.map(b => msgHelper.deserializeValue(b))
                                }
                            });
                        }

                        return result;
                    });
                    if (resolver.type == "seq_no")
                        resolver.resolver(results.length > 0 ? results[0] : null) // Return as a single object rather than an array.
                    delete ledgerQueryResolvers[m.reply_for];
                }
            }
            else {
                liblog(1, "Received unrecognized contract message: type:" + m.type);
                return false;
            }

            return true;
        }

        const messageHandler = async (rcvd) => {

            // Decode the received data buffer.
            // In browser, text(json) mode requires the buffer to be "decoded" to text before JSON parsing.
            const isTextMode = (connectionStatus < 2 || protocol == protocols.json);
            const data = (isBrowser && isTextMode) ? textDecoder.decode(rcvd.data) : rcvd.data;

            try {
                m = msgHelper.deserializeMessage(data);
            }
            catch (e) {
                liblog(1, e);
                liblog(0, "Exception deserializing: ");
                liblog(0, data || rcvd);

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
                liblog(0, "Closing connection to " + server);
            else
                liblog(0, "Disconnected from " + server);

            emitter = null;

            if (handshakeTimer)
                clearTimeout(handshakeTimer);

            // If there are any ongoing resolvers resolve them with error output.

            handshakeResolver && handshakeResolver(false);
            handshakeResolver = null;

            statResponseResolvers.forEach(resolver => resolver(null));
            statResponseResolvers = [];

            Object.values(contractInputResolvers).forEach(resolver => resolver({
                status: "failed",
                reason: "connection_error"
            }));
            contractInputResolvers = {};

            this.onClose && this.onClose();
            closeResolver && closeResolver();
        }

        const errorHandler = (e) => {
            handshakeResolver && handshakeResolver(false);
        }

        const wsSend = (msg) => {
            if (isString(msg))
                ws.send(textEncoder.encode(msg));
            else
                ws.send(msg);
        }

        this.isConnected = () => {
            return connectionStatus == 2;
        };

        this.connect = () => {
            liblog(0, "Connecting to " + server);
            return new Promise(resolve => {

                ws = isBrowser ? new WebSocket(server) : new WebSocket(server, { rejectUnauthorized: false });
                if (isBrowser)
                    ws.binaryType = "arraybuffer";

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
                wsSend(msgHelper.serializeObject(msg));
            }
            return p;
        }

        this.submitContractInput = async (input, nonce, maxLedger, isOffset) => {

            if (connectionStatus != 2)
                throw "Connection error.";
            if (maxLedger == 0)
                throw "Max ledger seq no. or offset cannot be 0.";
            if (!isOffset && !maxLedger)
                throw "Max ledger seq. no not specified.";

            // Use time-based incrementing nonce if not specified.
            if (!nonce)
                nonce = (new Date()).getTime().toString();
            else
                nonce = nonce.toString();

            // If max ledger is specified as offset, we need to get current ledger status and add the offset to it.
            if (isOffset) {
                if (!maxLedger)
                    maxLedger = 10; // Default offset applied if not specified.

                // Acquire the current ledger status and add the specified offset.
                const stat = await this.getStatus();
                if (!stat)
                    throw "Error retrieving ledger status."

                maxLedger += stat.ledgerSeqNo;
            }

            const inp = msgHelper.createContractInputComponents(input, nonce, maxLedger);

            const inputHashHex = msgHelper.stringifyValue(inp.hash);

            // Start waiting for this input's accept/rejected status response.
            const p = new Promise(resolve => {
                contractInputResolvers[inputHashHex] = resolve;
            });

            const msg = msgHelper.createContractInputMessage(inp.container, inp.sig);
            wsSend(msgHelper.serializeObject(msg));

            // We return the input hash and a promise which can be resolved to get the input submission status.
            return {
                hash: msgHelper.binaryEncode(inp.hash),
                submissionStatus: p
            };
        }

        this.sendContractReadRequest = (request) => {

            if (connectionStatus != 2)
                return Promise.resolve();

            const msg = msgHelper.createReadRequest(request);
            wsSend(msgHelper.serializeObject(msg));
            return Promise.resolve();
        }

        this.getLedgerBySeqNo = (seqNo, includeInputs, includeOutputs) => {
            if (connectionStatus != 2)
                return Promise.resolve(null);

            const msg = msgHelper.createLedgerQuery("seq_no", { "seq_no": seqNo }, includeInputs, includeOutputs);
            const p = new Promise(resolve => {
                ledgerQueryResolvers[msg.id] = {
                    type: "seq_no",
                    resolver: resolve
                };
            })

            wsSend(msgHelper.serializeObject(msg));
            return p;
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

        this.binaryDecode = (data) => {
            return protocol == protocols.json ? hexToUint8Array(data) : new Uint8Array(data.buffer);
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

        this.deserializeValue = (val) => {
            return protocol == protocols.json ? val : val.buffer;
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
            const sigBytes = sodium.crypto_sign_detached(userChallenge, keys.privateKey.slice(1));

            return {
                type: "user_challenge_response",
                sig: this.binaryEncode(sigBytes),
                pubkey: this.binaryEncode(keys.publicKey),
                server_challenge: serverChallenge,
                protocol: msgProtocol
            }
        }

        // Creates a signed contract input components
        this.createContractInputComponents = (input, nonce, maxLedgerSeqNo) => {

            if (input.length == 0)
                return null;

            const inpContainer = {
                input: this.serializeInput(input),
                nonce: nonce,
                max_ledger_seq_no: maxLedgerSeqNo
            }

            const serlializedInpContainer = this.serializeObject(inpContainer);
            const sigBytes = sodium.crypto_sign_detached(serlializedInpContainer, keys.privateKey.slice(1));

            // Input hash is the blake3 hash of the input signature.
            // The input hash can later be used to query input details from the ledger.
            const inputHash = new Uint8Array(blake3.hash(sigBytes));

            return {
                hash: inputHash,
                container: serlializedInpContainer,
                sig: sigBytes
            }
        }

        this.createContractInputMessage = (container, sig) => {

            return {
                type: "contract_input",
                input_container: container,
                sig: this.binaryEncode(sig)
            }
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

        this.createLedgerQuery = (filterBy, params, includeInputs, includeOutputs) => {

            const includes = [];
            if (includeInputs) includes.push("inputs");
            if (includeOutputs) includes.push("outputs");

            return {
                type: "ledger_query",
                id: "query_" + filterBy + "_" + (new Date()).getTime().toString(),
                filter_by: filterBy,
                params: params,
                include: includes
            }
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

    function arraysEqual(a, b) {
        if (a.length != b.length)
            return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i])
                return false;
        }
        return true;
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

        if (isBrowser) { // Browser
            if (!sodium) {
                sodium = window.sodium || await new Promise(resolve => {
                    window.sodium = {
                        onload: async (sodiumRef) => resolve(sodiumRef)
                    }
                })
            }
        }
        else { // nodejs
            if (!sodium)
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

    function setLogLevel(level) {
        logLevel = level;
    }

    function liblog(level, msg) {
        if (level >= logLevel)
            console.log(msg);
    }

    if (isBrowser) {
        window.HotPocket = {
            generateKeys,
            createClient,
            events,
            protocols,
            setBlake3,
            setLogLevel
        };
    }
    else {
        module.exports = {
            generateKeys,
            createClient,
            events,
            protocols,
            setLogLevel
        };
    }
})();