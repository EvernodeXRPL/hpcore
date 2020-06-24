const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const readline = require('readline')

// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e) => { console.log(e) })


function main() {

    var keys = sodium.crypto_sign_keypair()


    // check for client keys
    if (!fs.existsSync('.hp_client_keys')) {
        keys.privateKey = sodium.to_hex(keys.privateKey)
        keys.publicKey = sodium.to_hex(keys.publicKey)
        fs.writeFileSync('.hp_client_keys', JSON.stringify(keys))
    } else {
        keys = JSON.parse(fs.readFileSync('.hp_client_keys'))
        keys.privateKey = Uint8Array.from(Buffer.from(keys.privateKey, 'hex'))
        keys.publicKey = Uint8Array.from(Buffer.from(keys.publicKey, 'hex'))
    }


    var server = 'wss://localhost:8080'

    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]

    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]

    var ws = new ws_api(server, {
        rejectUnauthorized: false
    })

    /* anatomy of a public challenge
       {
       version: '0.1',
       type: 'public_challenge',
       challenge: '<hex string>'
       }
     */


    // if the console ctrl + c's us we should close ws gracefully
    process.once('SIGINT', function (code) {
        console.log('SIGINT received...');
        ws.close()
    });

    function create_input_container(inp) {
        
        let inp_container = {
            nonce: (new Date()).getTime().toString(),
            input: inp.toString('hex'),
            max_lcl_seqno: 9999999
        }
        let inp_container_bytes = JSON.stringify(inp_container);
        let sig_bytes = sodium.crypto_sign_detached(inp_container_bytes, keys.privateKey);

        let signed_inp_container = {
            type: "contract_input",
            input_container: inp_container_bytes.toString('hex'),
            sig: Buffer.from(sig_bytes).toString('hex')
        }

        return JSON.stringify(signed_inp_container);
    }

    function create_status_request() {
        let statreq = { type: 'stat' }
        return JSON.stringify(statreq);
    }

    function handle_public_challange(m) {
        let pkhex = 'ed' + Buffer.from(keys.publicKey).toString('hex');
        console.log('My public key is: ' + pkhex);

        // sign the challenge and send back the response
        var sigbytes = sodium.crypto_sign_detached(m.challenge, keys.privateKey);
        var response = {
            type: 'handshake_response',
            challenge: m.challenge,
            sig: Buffer.from(sigbytes).toString('hex'),
            pubkey: pkhex
        }

        ws.send(JSON.stringify(response))

        // start listening for stdin
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        console.log("Ready to accept inputs.")

        // Capture user input from the console.
        var input_pump = () => {
            rl.question('', (inp) => {

                let msgtosend = "";

                if (inp == "stat")
                    msgtosend = create_status_request();
                else {
                    var fileContent = fs.readFileSync(inp);
                    msgtosend = create_input_container(fileContent);

                    console.log("Sending file (len: " + fileContent.length / 1024 + " KB)");
                }

                ws.send(msgtosend)

                input_pump()
            })
        }
        input_pump();
    }

    ws.on('message', (data) => {

        try {
            m = JSON.parse(data)
        } catch (e) {
            console.log("Exception: " + data);
            return
        }

        if (m.type == 'handshake_challenge') {
            handle_public_challange(m);
        }
        else if (m.type == 'contract_output') {
            console.log("Contract says: " + Buffer.from(m.content, 'hex').toString());
        }
        else if (m.type == 'contract_input_status') {
            if (m.status != "accepted")
                console.log("Input status: " + m.status);
        }
        else {
            console.log(m);
        }

    });

    ws.on('close', () => {
        console.log('Server disconnected.');
    });
}
