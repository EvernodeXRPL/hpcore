// Usage:
// node text-client.js [json|bson]
// node text-client.js [json|bson] [<port>]
// node text-client.js [json|bson] [<ip>] [<port>]

const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const readline = require('readline')
const bson = require('bson');
const { exit } = require('process');

function main() {

    // We use json protocol for messages until handshake completion.
    let is_json = true;

    if (process.argv.length < 3) {
        console.log("Not enough arguments. 'protocol: [json|bson] required")
        return;
    }
    const protocol = process.argv[2];
    if (protocol != 'json' && protocol != 'bson') {
        console.log("Not enough arguments. 'protocol: [json|bson] required")
        return;
    }

    let server = 'wss://localhost:8080'
    if (process.argv.length == 4) server = 'wss://localhost:' + process.argv[3]
    if (process.argv.length == 5) server = 'wss://' + process.argv[3] + ':' + process.argv[4]

    const ws = new ws_api(server, {
        rejectUnauthorized: false
    })

    let keys = {};
    const key_file = '.hp_client_keys';
    if (!fs.existsSync(key_file)) {
        keys = sodium.crypto_sign_keypair();
        keys.privateKey = sodium.to_hex(keys.privateKey)
        keys.publicKey = sodium.to_hex(keys.publicKey)
        fs.writeFileSync(key_file, JSON.stringify(keys))
    } else {
        keys = JSON.parse(fs.readFileSync(key_file))
        keys.privateKey = Uint8Array.from(Buffer.from(keys.privateKey, 'hex'))
        keys.publicKey = Uint8Array.from(Buffer.from(keys.publicKey, 'hex'))
    }

    const pkhex = 'ed' + Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    // if the console ctrl + c's us we should close ws gracefully
    process.once('SIGINT', function () {
        console.log('SIGINT received...');
        ws.close();
    });

    function encode_buffer(buffer) {
        return is_json ? buffer.toString('hex') : buffer;
    }

    function serialize_object(obj) {
        return is_json ? Buffer.from(JSON.stringify(obj)) : bson.serialize(obj);
    }

    function deserialize_message(m) {
        return is_json ? JSON.parse(m) : bson.deserialize(m);
    }

    function create_handshake_response(challenge) {
        const sig_bytes = sodium.crypto_sign_detached(challenge, keys.privateKey);
        return {
            type: 'handshake_response',
            challenge: challenge,
            sig: encode_buffer(Buffer.from(sig_bytes)),
            pubkey: pkhex,
            protocol: protocol
        }
    }

    function create_input_container(inp) {

        if (inp.length == 0)
            return null;

        const inp_container = {
            nonce: (new Date()).getTime().toString(),
            input: encode_buffer(Buffer.from(inp)),
            max_lcl_seqno: 999999999
        }

        const inp_container_bytes = serialize_object(inp_container);
        const sig_bytes = Buffer.from(sodium.crypto_sign_detached(inp_container_bytes, keys.privateKey));

        const signed_inp_container = {
            type: "contract_input",
            input_container: encode_buffer(inp_container_bytes),
            sig: encode_buffer(sig_bytes)
        }

        return signed_inp_container;
    }

    function create_read_request_container(inp) {

        if (inp.length == 0)
            return null;

        return {
            type: "contract_read_request",
            content: encode_buffer(Buffer.from(inp))
        }
    }

    function create_status_request() {
        return { type: 'stat' };
    }

    function handle_handshake_challange(m) {

        // sign the challenge and send back the response
        const response = create_handshake_response(m.challenge);
        ws.send(serialize_object(response));
        is_json = (protocol == 'json');

        // start listening for stdin
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        console.log("Ready to accept inputs.");

        // Capture user input from the console.
        const input_pump = () => {
            rl.question('', (inp) => {

                let msg;
                if (inp == "stat")
                    msg = create_status_request();
                else if (inp.startsWith("read "))
                    msg = create_read_request_container(inp.substr(5));
                else
                    msg = create_input_container(inp);

                if (msg != null)
                    ws.send(serialize_object(msg))

                input_pump();
            })
        }
        input_pump();
    }

    ws.on('message', (received_msg) => {

        try {
            m = deserialize_message(received_msg);
        } catch (e) {
            console.log("Exception deserializing: " + received_msg);
            return;
        }

        if (m.type == 'handshake_challenge') {
            handle_handshake_challange(m);
        }
        else if (m.type == 'contract_output' || m.type == 'contract_read_response') {
            const contract_reply = is_json ? Buffer.from(m.content, 'hex').toString() : m.content.toString();
            console.log(contract_reply);
        }
        else if (m.type == 'contract_input_status') {
            if (m.status != "accepted")
                console.log("Input status: " + m.status + " | reason: " + m.reason);
        }
        else {
            console.log(m);
        }

    });

    ws.on('close', () => {
        console.log('Server disconnected.');
        exit();
    });
}

// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e) => { console.log(e) })