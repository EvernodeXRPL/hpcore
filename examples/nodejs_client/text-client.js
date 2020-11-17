const fs = require('fs');
const readline = require('readline');
const { exit } = require('process');
const { HotPocketClient, HotPocketKeyGenerator, HotPocketEvents } = require('./hp-client-lib');

async function main() {

    const keys = await HotPocketKeyGenerator.generate();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    let server = 'wss://localhost:8080'
    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]
    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]
    const hpc = new HotPocketClient(server, keys);

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        exit();
    }
    console.log('HotPocket Connected.');

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocketEvents.disconnect, () => {
        console.log('Server disconnected');
        exit();
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocketEvents.contractOutput, (output) => {
        console.log("Contract output>> " + Buffer.from(output, "hex"));
    })

    // This will get fired when contract sends a read response.
    hpc.on(HotPocketEvents.contractReadResponse, (response) => {
        console.log("Contract read response>> " + Buffer.from(response, "hex"));
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