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

    const eventsObjects = {
        disconnect: new Event("disconnect"),
        contractOutput: new Event("contractOutput"),
        contractReadResponse: new Event("contractReadResponse")
    }
    Object.freeze(eventsObjects);

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
                const binPrivateKey = Buffer.from(privateKeyHex, "hex");
                return {
                    privateKey: Uint8Array.from(binPrivateKey),
                    publicKey: Uint8Array.from(binPrivateKey.slice(32))
                }
            }
        },
    }

    HotPocketClient = function HotPocketClient(server, keys) {

        let ws = null;
        const protocol = protocols.json; // We only support json in browser.
        const msgHelper = new MessageHelper(keys, protocol);
        const emitter = new EventTarget();

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

                    emitter.dispatchEvent(eventsObjects.disconnect);
                });

                ws.onmessage = async (rcvd) => {

                    console.log(rcvd);
                    return;

                    msg = (handshakeResolver || protocol == protocols.json) ?
                        await rcvd.data.text() :
                        Buffer.from(await rcvd.data.arrayBuffer());

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
                        const decoded = msgHelper.binaryDecode(m.content);
                        emitter.dispatchEvent(eventsObjects.contractReadResponse, decoded);
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
                        const decoded = msgHelper.binaryDecode(m.content);
                        emitter.dispatchEvent(eventsObjects.contractOutput, decoded);
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
            emitter.addEventListener(event, listener);
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
            const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
            return protocol == protocols.json ? buffer.toString("hex") : buffer;
        }

        this.binaryDecode = function (content) {
            return (protocol == protocols.json) ? Buffer.from(content, "hex") : content.buffer;
        }

        this.serializeObject = function (obj) {
            return protocol == protocols.json ? JSON.stringify(obj) : null;
        }

        this.deserializeMessage = function (m) {
            return protocol == protocols.json ? JSON.parse(m) : null;
        }

        this.serializeInput = function (input) {
            return protocol == protocols.json ?
                input.toString() :
                Buffer.isBuffer(input) ? input : Buffer.from(input);
        }

        this.createHandshakeResponse = function (challenge) {
            // For handshake response encoding Hot Pocket always uses json.
            // Handshake response will specify the protocol to use for subsequent messages.
            const sigBytes = sodium.crypto_sign_detached(challenge, keys.privateKey);
            return {
                type: "handshake_response",
                challenge: challenge,
                sig: Buffer.from(sigBytes).toString("hex"),
                pubkey: "ed" + Buffer.from(keys.publicKey).toString("hex"),
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
            const sigBytes = sodium.crypto_sign_detached(Buffer.from(serlializedInpContainer), keys.privateKey);

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