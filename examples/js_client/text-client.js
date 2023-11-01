const readline = require('readline');
const HotPocket = require('hotpocket-js-client');

async function main() {

    // Set HP lib log level. 0=info, 1=error
    // HotPocket.setLogLevel(1);

    const keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    let server = 'wss://localhost:8080'
    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]
    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]

    // Simple connection to single server without any validations.
    const hpc = await HotPocket.createClient([server], keys);

    // Maintain multiple connections with contract id/version and trusted server key validation.
    // const hpc = await HotPocket.createClient(
    //     [
    //         "wss://localhost:8081",
    //         "wss://localhost:8082",
    //         "wss://localhost:8083"
    //     ],
    //     keys,
    //     {
    //         contractId: "3c349abe-4d70-4f50-9fa6-018f1f2530ab",
    //         contractVersion: "1.0",
    //         trustedServerKeys: [
    //             "ed5597c207bbd251997b7133d5d83a2c6ab9600810edf0bdb43f4004852b8c9e17",
    //             "ed0b2ffd75b67c3979d3c362d8350ec190f053fa27d3dfcb2eced426efd1d3affc",
    //             "edd2e1a817387d68adf8adb1d0b339e3f04868c3c81bf6a7472647f10657e31aa1"
    //         ],
    //         protocol: HotPocket.protocols.json,
    //         requiredConnectionCount: 2,
    //         connectionTimeoutMs: 5000
    //     });

    // We'll register for HotPocket events before connecting.

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocket.events.disconnect, () => {
        console.log('Disconnected');
        rl.close();
    })

    // This will get fired as servers connects/disconnects.
    hpc.on(HotPocket.events.connectionChange, (server, action) => {
        console.log(server + " " + action);
    })

    // This will get fired when contract sends outputs.
    hpc.on(HotPocket.events.contractOutput, (r) => {
        r.outputs.forEach(o => {
            const outputLog = o.length <= 512 ? o : `[Big output (${o.length / 1024} KB)]`;
            console.log(`Output (ledger:${r.ledgerSeqNo})>> ${outputLog}`);
        });
    })

    // This will get fired when the unl public key list changes.
    hpc.on(HotPocket.events.unlChange, (unl) => {
        console.log("New unl received:");
        console.log(unl); // unl is an array of public keys.
    })

    // This will get fired when any ledger event occurs (ledger created, sync status change).
    hpc.on(HotPocket.events.ledgerEvent, (ev) => {
        console.log(ev);
    })

    // This will get fired when any health event occurs (proposal stats, connectivity changes...).
    hpc.on(HotPocket.events.healthEvent, (ev) => {
        console.log(ev);
    })

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        return;
    }
    console.log('HotPocket Connected.');

    // After connecting, we can subscribe to events from the HotPocket node.
    // await hpc.subscribe(HotPocket.notificationChannels.unlChange);
    // await hpc.subscribe(HotPocket.notificationChannels.ledgerEvent);
    // await hpc.subscribe(HotPocket.notificationChannels.healthEvent);

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

    console.log("Ready to accept inputs.");

    const input_pump = () => {
        rl.question('', (inp) => {

            if (inp.length > 0) {
                if (inp.startsWith("read ")) {
                    hpc.submitContractReadRequest(inp.substr(5)).then(reply => console.log(reply));
                }
                else if (inp.startsWith("ledger ")) {
                    hpc.getLedgerBySeqNo(parseInt(inp.substr(7)), true, true)
                        .then(result => console.log(result));
                }
                else if (inp.startsWith("health ")) {
                    if (inp.endsWith("on"))
                        hpc.subscribe(HotPocket.notificationChannels.healthEvent);
                    else if (inp.endsWith("off"))
                        hpc.unsubscribe(HotPocket.notificationChannels.healthEvent);
                }
                else if (inp === "stat") {
                    hpc.getStatus().then(stat => console.log(stat));
                }
                else if (inp.startsWith("hpsh ")) {
                    hpc.submitHpshRequest(inp.substr(5)).then(id => {
                        hpc.on(id, (reply) => {
                            if (reply.data)
                                console.log(reply.data);
                            else
                                console.error(reply.error);
                        })
                    });
                }
                else {

                    if (inp.startsWith("upload ")) {
                        const size = parseInt(inp.split(" ")[1]);
                        if (!isNaN(size)) {
                            inp = "A".repeat(size * 1024 * 1024);
                            console.log("Uploading " + size + " MB payload...");
                        }
                    }

                    hpc.submitContractInput(inp).then(input => {
                        // console.log(input.hash);
                        input.submissionStatus.then(s => {
                            if (s.status != "accepted")
                                console.log(s.reason);
                        });
                    })

                }
            }

            input_pump();
        })
    }
    input_pump();
}

main();