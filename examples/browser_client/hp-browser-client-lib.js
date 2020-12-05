window.HotPocket = (() => {

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

    const fromHexString = hexString =>
        new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const toHexString = bytes =>
        bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

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

    HotPocketClient = function HotPocketClient(contractId, server, keys) {

        let ws = null;
        const protocol = protocols.json; // We only support json in browser.
        const msgHelper = new MessageHelper(keys, protocol);
        const emitter = new EventEmitter();

        let handshakeResolver = null;
        let statResponseResolvers = [];
        let contractInputResolvers = {};

        this.connect = function () {
            return new Promise(resolve => {

                handshakeResolver = resolve;

                ws = new WebSocket(server);

                ws.addEventListener("close", () => {
                    // If there are any ongoing resolvers resolve them with error output.

                    handshakeResolver && handshakeResolver(false);
                    handshakeResolver = null;

                    statResponseResolvers.forEach(resolver => resolver(null));
                    statResponseResolvers = [];

                    Object.values(contractInputResolvers).forEach(resolver => resolver(null));
                    contractInputResolvers = {};

                    emitter.emit(events.disconnect);
                });

                ws.onmessage = async (rcvd) => {

                    msg = await rcvd.data.text();

                    try {
                        // Use JSON if we are still in handshake phase.
                        m = handshakeResolver ? JSON.parse(msg) : msgHelper.deserializeMessage(msg);
                    } catch (e) {
                        console.log(e);
                        console.log("Exception deserializing: ");
                        console.log(msg)
                        return;
                    }

                    if (m.type == 'handshake_challenge') {
                        // Check whether contract id is matching if specified.
                        if (contractId && m.contract_id != contractId) {
                            console.error("Contract id mismatch.")
                            ws.close();
                        }

                        // sign the challenge and send back the response
                        const response = msgHelper.createHandshakeResponse(m.challenge);
                        ws.send(JSON.stringify(response));

                        setTimeout(() => {
                            // If we are still connected, report handshaking as successful.
                            // (If websocket disconnects, handshakeResolver will be null)
                            handshakeResolver && handshakeResolver(true);
                            handshakeResolver = null;
                        }, 100);
                    }
                    else if (m.type == 'contract_read_response') {
                        const decoded = msgHelper.deserializeOutput(msgHelper.binaryDecode(m.content));
                        emitter.emit(events.contractReadResponse, decoded);
                    }
                    else if (m.type == 'contract_input_status') {
                        const sigKey = (typeof m.input_sig === "string") ? m.input_sig : m.input_sig.toString("hex");
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
                        const decoded = msgHelper.deserializeOutput(msgHelper.binaryDecode(m.content));
                        emitter.emit(events.contractOutput, decoded);
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
                    }
                }
            });
        };

        this.on = function (event, listener) {
            emitter.on(event, listener);
        }

        this.close = function () {
            return new Promise(resolve => {
                try {
                    ws.addEventListener("close", resolve);
                    ws.close();
                } catch (error) {
                    resolve();
                }
            })
        }

        this.getStatus = function () {
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

        this.sendContractInput = async function (input, nonce = null, maxLclOffset = null) {

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
            const sigKey = (typeof msg.sig === "string") ? msg.sig : msg.sig.toString("hex");
            const p = new Promise(resolve => {
                contractInputResolvers[sigKey] = resolve;
            });

            ws.send(msgHelper.serializeObject(msg));
            return p;
        }

        this.sendContractReadRequest = function (request) {
            const msg = msgHelper.createReadRequest(request);
            ws.send(msgHelper.serializeObject(msg));
        }
    }

    function MessageHelper(keys, protocol) {

        this.binaryEncode = function (data) {
            return toHexString(data);
        }

        this.binaryDecode = function (content) {
            return fromHexString(content);
        }

        this.serializeObject = function (obj) {
            return JSON.stringify(obj);
        }

        this.deserializeMessage = function (m) {
            return JSON.parse(m);
        }

        this.serializeInput = function (input) {
            return (typeof input === 'string' || input instanceof String) ? input : input.toString();
        }

        this.deserializeOutput = function (bytes) {
            return new TextDecoder().decode(bytes);
        }

        this.createHandshakeResponse = function (challenge) {
            // For handshake response encoding Hot Pocket always uses json.
            // Handshake response will specify the protocol to use for subsequent messages.
            const sigBytes = sodium.crypto_sign_detached(challenge, keys.privateKey);

            return {
                type: "handshake_response",
                challenge: challenge,
                sig: toHexString(sigBytes),
                pubkey: "ed" + toHexString(keys.publicKey),
                protocol: protocol
            }
        }

        this.createContractInput = function (input, nonce, maxLclSeqNo) {

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

        this.createReadRequest = function (request) {

            if (request.length == 0)
                return null;

            return {
                type: "contract_read_request",
                content: this.serializeInput(request)
            }
        }

        this.createStatusRequest = function () {
            return { type: 'stat' };
        }
    }

    return {
        KeyGenerator: KeyGenerator,
        Client: HotPocketClient,
        events: events,
    }
})();