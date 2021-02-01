// HotPocket test client to collect metrics.
// This assumes the HotPocket server we are connecting to is hosting the echo contract.

const HotPocket = require('./hp-client-lib');

let server = 'wss://localhost:8080';
if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2];
if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3];
console.log("Server: " + server);

async function main() {

    HotPocket.setLogLevel(1);

    const tests = {
        "Single user read requests": singleUserReadRequests,
        "Single user Input/Output": singleUserInputOutput,
        "Multi user read requests": multiUserReadRequests,
        "Multi user Input/Output": multiUserInputOutput
    };

    for (const test in tests) {

        console.log(test + "...");
        const start = new Date();

        await tests[test]();

        const end = new Date();
        const duration = end.getTime() - start.getTime();

        console.log(duration + "ms");
    }
}

async function createClient() {
    const keys = await HotPocket.generateKeys();

    const hpc = await HotPocket.createClient([server], keys,
        {
            contractId: "3c349abe-4d70-4f50-9fa6-018f1f2530ab",
            protocol: HotPocket.protocols.json
        });

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        throw "Connection failed."
    }

    return hpc;
}

function singleUserReadRequests() {

    return new Promise(async resolve => {

        const payload = "A".repeat(10 * 1024);
        const requestCount = 10;
        let respCount = 0;

        const hpc = await createClient();
        hpc.on(HotPocket.events.contractReadResponse, (response) => {
            respCount++;
            if (respCount == requestCount)
                hpc.close().then(() => resolve());
        });

        for (let i = 0; i < requestCount; i++) {
            hpc.sendContractReadRequest(payload);
        }
    })
}

function singleUserInputOutput() {

    return new Promise(async (resolve) => {

        const payload = "A".repeat(10 * 1024);
        const requestCount = 10;
        let respCount = 0;

        const hpc = await createClient();
        hpc.on(HotPocket.events.contractOutput, (response) => {
            respCount++;
            if (respCount == requestCount)
                hpc.close().then(() => resolve());
        });

        for (let i = 0; i < requestCount; i++) {
            const nonce = i.toString().padStart(5);
            await hpc.sendContractInput(payload, nonce, 20);
        }
    })
}

function multiUserReadRequests() {

    const userCount = 10;
    const tasks = [];

    for (let i = 0; i < userCount; i++) {
        tasks.push(singleUserReadRequests());
    }
    return Promise.all(tasks);
}

function multiUserInputOutput() {

    const userCount = 10;
    const tasks = [];

    for (let i = 0; i < userCount; i++) {
        tasks.push(singleUserInputOutput());
    }
    return Promise.all(tasks);
}

main();