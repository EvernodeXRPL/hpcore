const fs = require('fs')
const readline = require('readline')
const sodium = require('libsodium-wrappers')
const { exit } = require('process');
const { HotPocketClient } = require('./hp-client-lib');

async function main() {

    await sodium.ready;

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

    const hpc = new HotPocketClient("wss://localhost:8081", "json", keys);
    hpc.on('disconnect', () => {
        console.log('server diconnected');
        exit;
    })

    if (!await hpc.connect()) {
        console.log('Connection failed.');
        exit;
    }
    console.log('connected');


    let stat = await hpc.getStatus();
    console.log(stat);

    await hpc.close();
    console.log('hpc closed');


    // start listening for stdin
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    const input_pump = () => {
        rl.question('', (inp) => {

            if (inp == "exit") {
                hpc.disconnect();
            }

            input_pump();
        })
    }
    input_pump();
}

main();