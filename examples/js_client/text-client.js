const readline = require('readline');
const HotPocket = require('./hp-client-lib');

async function main() {

    const keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    let server = 'wss://localhost:8080'
    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]
    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]
    const hpc = await HotPocket.createClient([server], keys);

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        return;
    }
    console.log('HotPocket Connected.');

    // start listening for stdin
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    // On ctrl + c we should close HP connection gracefully.
    rl.on('SIGINT', () => {
        console.log('SIGINT received...');
        rl.close();
        hpc.close();
    });

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocket.events.disconnect, () => {
        console.log('Disconnected');
        rl.close();
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocket.events.contractOutput, (output) => {
        console.log("Contract output>> " + output);
    })

    // This will get fired when contract sends a read response.
    hpc.on(HotPocket.events.contractReadResponse, (response) => {
        console.log("Contract read response>> " + response);
    })

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