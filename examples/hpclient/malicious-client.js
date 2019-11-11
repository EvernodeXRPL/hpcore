//
// HotPocket client example code adopted from:
// https://github.com/codetsunami/hotpocket/blob/master/hp_client.js
//

const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const readline = require('readline')

// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e) => { console.log(e) })


function main() {

    if (process.argv.length != 6) {
        console.log("Incorrect format");
        console.log("node client.js <ip_address> <port> <bytes_per_message> <interval>");
        process.exit();
    }

    var args = process.argv.slice(2);
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

    if (process.argv.length == 3) server = 'wss://localhost:' + args[0]

    if (process.argv.length == 4) server = 'wss://' + args[0] + ':' + args[1]

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

    ws.on('message', (m) => {
        console.log("-----Received raw message-----")
        console.log(m.toString())
        console.log("------------------------------")

        try {
            m = JSON.parse(m)
        } catch (e) {
            return
        }

        if (m.type != 'public_challenge') return

        console.log("Received challenge message")
        console.log(m)

        let pkhex = 'ed' + Buffer.from(keys.publicKey).toString('hex');
        console.log('My public key is: ' + pkhex);

        // sign the challenge and send back the response
        var sigbytes = sodium.crypto_sign_detached(m.challenge, keys.privateKey);
        var response = {
            type: 'challenge_resp',
            challenge: m.challenge,
            sig: Buffer.from(sigbytes).toString('hex'),
            pubkey: pkhex
        }

        console.log('Sending challenge response.');
        ws.send(JSON.stringify(response));
        
        setInterval(() => {
            var message = generateRandomMessage(args[2]);
            console.log("Message :" + message);
            ws.send(message);
        }, args[3]);

    });

    ws.on('close', () => {
        console.log('Server disconnected.');
    });
}

function generateRandomMessage(length) {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}
