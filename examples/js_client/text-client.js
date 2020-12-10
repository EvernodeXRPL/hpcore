const readline = require('readline');
const { exit } = require('process');
const sodium = require('libsodium-wrappers');
const HotPocket = require('./hp-client-lib');

async function main() {

    await sodium.ready;
    HotPocket.initSodium(sodium);

    const keys = await HotPocket.KeyGenerator.generate();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    let server = 'wss://localhost:8080'
    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]
    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]
    const hpc = new HotPocket.Client(null, null, keys, [server]);

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        exit();
    }
    console.log('HotPocket Connected.');

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocket.events.disconnect, () => {
        console.log('Server disconnected');
        exit();
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocket.events.contractOutput, (output) => {
        console.log("Contract output>> " + output);
    })

    // This will get fired when contract sends a read response.
    hpc.on(HotPocket.events.contractReadResponse, (response) => {
        console.log("Contract read response>> " + response);
    })

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
        rl.question('', (inp) => {

            if (inp.length > 0) {
                if (inp.startsWith("read "))
                    hpc.sendContractReadRequest(inp.substr(5))
                else {
                    hpc.sendContractInput(inp).then(submissionStatus => {
                        if (submissionStatus && submissionStatus != "ok")
                            console.log("Input submission failed. reason: " + submissionStatus);
                    });
                }
            }

            input_pump();
        })
    }
    input_pump();
}

main();