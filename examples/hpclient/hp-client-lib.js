const ws_api = require('ws');
const sodium = require('libsodium-wrappers');
const EventEmitter = require('events');
const bson = require('bson');

const protocols = {
    JSON: "json",
    BSON: "bson"
}
Object.freeze(protocols);

const events = {
    disconnect: "disconnect",
    contractOutput: "contractOutput",
    contractReadResponse: "contractReadResponse"
}
Object.freeze(events);

function HotPocketClient(server, protocol, keys) {

    if (protocol != protocols.JSON && protocol != protocols.BSON)
        throw new Error("Protocol: 'json' or 'bson' expected.");

    let ws = null;
    const msgHelper = new MessageHelper(keys, protocol);
    const emitter = new EventEmitter();

    let handshakeResolver = null;
    let statResponseResolver = null;
    let contractInputResolvers = {};

    this.connect = function () {
        return new Promise(resolve => {

            handshakeResolver = resolve;

            ws = new ws_api(server, {
                rejectUnauthorized: false
            })

            ws.on('close', () => {

                // If there are any ongoing resolvers resolve them with error output.

                handshakeResolver && handshakeResolver(false);
                handshakeResolver = null;

                statResponseResolver && statResponseResolver(null);
                statResponseResolver = null;

                Object.values(contractInputResolvers).forEach(resolver => resolver(null));
                contractInputResolvers = {};

                emitter.emit(events.disconnect);
            });

            ws.on('message', (msg) => {
                try {
                    // Use JSON if we are still in handshake phase.
                    m = handshakeResolver ? JSON.parse(msg) : msgHelper.deserializeMessage(msg);
                } catch (e) {
                    console.log("Exception deserializing: " + received_msg);
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
                    const decoded = msgHelper.binaryDecode(m.content);
                    emitter.emit(events.contractOutput, decoded);
                }
                else if (m.type == "stat_response") {
                    statResponseResolver && statResponseResolver({
                        lcl: m.lcl,
                        lclSeqNo: m.lcl_seqno
                    });
                    statResponseResolver = null;
                }
                else {
                    console.log("Received unrecognized message: type:" + m.type);
                }
            });
        });
    };

    this.on = function (event, listener) {
        emitter.on(event, listener);
    }

    this.close = function () {
        Promise.resolve().then
        return new Promise(resolve => {
            try {
                ws.removeAllListeners("close");
                ws.on("close", resolve);
                ws.close();
            } catch (error) {
                resolve();
            }
        })
    }

    this.getStatus = function () {
        const msg = msgHelper.createStatusRequest();
        const p = new Promise(resolve => {
            statResponseResolver = resolve;
        });

        ws.send(msgHelper.serializeObject(msg));
        return p;
    }

    this.sendContractInput = async function (input, nonce = null, maxLclOffset = null) {

        if (!maxLclOffset)
            maxLclOffset = 10;

        if (!nonce)
            nonce = (new Date()).getTime().toString();

        // Acquire the current lcl and add the specified offset.
        const stat = await this.getStatus();
        if (!stat)
            return new Promise(resolve => resolve(null));
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
        return protocol == protocols.JSON ? buffer.toString("hex") : buffer;
    }

    this.binaryDecode = function (content) {
        return (protocol == protocols.JSON) ? Buffer.from(content, "hex") : content.buffer;
    }

    this.serializeObject = function (obj) {
        return protocol == protocols.JSON ? Buffer.from(JSON.stringify(obj)) : bson.serialize(obj);
    }

    this.deserializeMessage = function (m) {
        return protocol == protocols.JSON ? JSON.parse(m) : bson.deserialize(m);
    }

    this.createHandshakeResponse = function (challenge) {
        // For handshake response encoding we Hot Pocket always use json.
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
            input: this.binaryEncode(input),
            nonce: nonce,
            max_lcl_seqno: maxLclSeqNo
        }
        
        const inpContainerBytes = this.serializeObject(inpContainer);
        const sigBytes = sodium.crypto_sign_detached(Buffer.from(inpContainerBytes), keys.privateKey);

        const signedInpContainer = {
            type: "contract_input",
            input_container: this.binaryEncode(inpContainerBytes),
            sig: this.binaryEncode(sigBytes)
        }

        return signedInpContainer;
    }

    this.createReadRequest = function (request) {

        if (request.length == 0)
            return null;

        return {
            type: "contract_read_request",
            content: this.binaryEncode(request)
        }
    }

    this.createStatusRequest = function () {
        return { type: 'stat' };
    }
}

module.exports = {
    HotPocketClient,
    HotPocketProtocols: protocols,
    HotPocketEvents: events
};