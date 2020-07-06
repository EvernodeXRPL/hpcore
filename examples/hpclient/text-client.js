const fs = require('fs')
const readline = require('readline')
const sodium = require('libsodium-wrappers')
const { exit } = require('process');
const { HotPocketClient, HotPocketProtocols, HotPocketEvents } = require('./hp-client-lib');

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

    const hpc = new HotPocketClient("wss://localhost:8081", HotPocketProtocols.JSON, keys);

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        exit;
    }

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocketEvents.disconnect, () => {
        console.log('Server diconnected');
        exit;
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocketEvents.contractOutput, (output) => {
        console.log("Contract output>> " + Buffer.from(output, "hex"));
    })

    // This will get fired when contract sends a read response.
    hpc.on(HotPocketEvents.contractReadResponse, (response) => {
        console.log("Contract read response>> " + Buffer.from(response, "hex"));
    })

    console.log('HotPocket Connected.');

    // On ctrl + c we should close HP connection gracefully.
    process.once('SIGINT', function () {
        console.log('SIGINT received...');
        hpc.close();
    });

    // start listening for stdin
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    console.log("Ready to accept inputs.");

    const input_pump = () => {
        rl.question('', async (inp) => {

            if (inp.startsWith("read "))
                hpc.sendContractReadRequest(inp.substr(5))
            else {
                const submissionStatus = await hpc.sendContractInput(inp);
                if (submissionStatus != "ok")
                    console.log("Input submission failed. reason: " + submissionStatus);
            }

            input_pump();
        })
    }
    input_pump();
}

main();