const ws_api = require('ws');
const sodium = require('libsodium-wrappers');
const EventEmitter = require('events');

const protocols = {
    JSON: "json",
    BSON: "bson"
}
Object.freeze(protocols);

const events = {
    disconnect: "disconnect"
}
Object.freeze(events);

function HotPocketClient(server, protocol, keys) {

    if (protocol != protocols.JSON || protocol == protocols.BSON)
        throw new Error("Protocol: 'json' or 'bson' expected.");

    let ws = null;
    const msgHelper = new MessageHelper(keys);
    const emitter = new EventEmitter();

    let statResponseResolver = null;

    this.connect = function () {
        return new Promise((resolve, reject) => {

            let handshakeComplete = false;

            ws = new ws_api(server, {
                rejectUnauthorized: false
            })

            ws.on('close', () => {
                if (!handshakeComplete)
                    reject();
                else
                    emitter.emit(events.disconnect);
            });

            ws.on('message', (msg) => {
                try {
                    m = msgHelper.deserializeMessage(msg);
                } catch (e) {
                    console.log("Exception deserializing: " + received_msg);
                    return;
                }
                console.log(m);

                if (m.type == 'handshake_challenge') {
                    // sign the challenge and send back the response
                    const response = msgHelper.createHandshakeResponse(m.challenge, protocol);
                    ws.send(msgHelper.serializeObject(response));

                    msgHelper.setProtocol(protocol);
                    handshakeComplete = true;
                    resolve();
                }
                else if (m.type == 'contract_output') {
                    const decoded = msgHelper.decodeContent(m.content);
                    this.onContractOutput && this.onContractOutput(decoded);
                }
                else if (m.type == 'contract_read_response') {
                    const decoded = msgHelper.decodeContent(m.content);
                    this.onContractReadResponse && this.onContractReadResponse(decoded);
                }
                else if (m.type == 'contract_input_status') {
                    const inputSig = msgHelper.decodeContent(m.input_sig);
                    if (m.status == "accepted")
                        this.onContractInputAccepted && this.onContractInputAccepted(inputSig);
                    else
                        this.onContractInputRejected && this.onContractInputRejected(inputSig);
                }
                else if (m.type == "stat_response") {
                    console.log(m);
                    //delete m.type;
                    statResponseResolver && statResponseResolver(m);
                    statResponseResolver = null;
                }
                else {
                    console.log("Received unrecognized message: type:" + m.type);
                }
            });
        });
    }

    this.on = function (event, listener) {
        emitter.on(event, listener);
    }

    this.close = function () {
        return new Promise(resolve => {
            ws.removeAllListeners('close');
            ws.on('close', resolve);
            ws.close();
        })
    }

    this.getStatus = function () {
        const msg = msgHelper.createStatusRequest();
        console.log(msg);
        ws.send(msgHelper.serializeObject(msg));
        return new Promise(resolve => {
            resolve();
            //statResponseResolver = resolve;
        });
    }
}

function MessageHelper(keys) {

    protocol = "json";

    this.setProtocol = function (newProtocol) {
        protocol = newProtocol;
    }

    this.encodeBuffer = function (buffer) {
        return protocol == protocols.JSON ? buffer.toString('hex') : buffer;
    }

    this.decodeContent = function (content) {
        return protocol == protocols.JSON ? Buffer.from(content, 'hex') : content;
    }

    this.serializeObject = function (obj) {
        return protocol == protocols.JSON ? Buffer.from(JSON.stringify(obj)) : bson.serialize(obj);
    }

    this.deserializeMessage = function (m) {
        return protocol == protocols.JSON ? JSON.parse(m) : bson.deserialize(m);
    }

    this.createHandshakeResponse = function (challenge, protocol) {
        const sigBytes = sodium.crypto_sign_detached(challenge, keys.privateKey);
        return {
            type: 'handshake_response',
            challenge: challenge,
            sig: this.encodeBuffer(Buffer.from(sigBytes)),
            pubkey: this.encodeBuffer(Buffer.from(keys.publicKey)),
            protocol: protocol
        }
    }

    this.createContractInput = function (input, maxLclSeqNo) {

        if (input.length == 0)
            return null;

        const inpContainer = {
            nonce: (new Date()).getTime().toString(),
            input: encodeBuffer(Buffer.from(input)),
            max_lcl_seqno: maxLclSeqNo
        }

        const inpContainerBytes = serializeObject(inpContainer);
        const sigBytes = Buffer.from(sodium.crypto_sign_detached(inpContainerBytes, keys.privateKey));

        const signedInpContainer = {
            type: "contract_input",
            input_container: encodeBuffer(inpContainerBytes),
            sig: encodeBuffer(sigBytes)
        }

        return signedInpContainer;
    }

    this.createReadRequest = function (request) {

        if (request.length == 0)
            return null;

        return {
            type: "contract_read_request",
            content: encodeBuffer(Buffer.from(request))
        }
    }

    this.createStatusRequest = function () {
        return { type: 'stat' };
    }
}

module.exports = {
    HotPocketClient
};