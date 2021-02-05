// HotPocket test client to collect metrics.
// This assumes the HotPocket server we are connecting to is hosting the echo contract.

const HotPocket = require('../../examples/js_client/hp-client-lib');

let server = 'wss://localhost:8080';
if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2];
if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3];
console.log("Server: " + server);

async function main() {

    HotPocket.setLogLevel(1);

    const tests = {
        "Large payload": () => largePayload(2),
        "Single user read requests": () => singleUserReadRequests(10, 10),
        "Single user Input/Output": () => singleUserInputOutput(10, 10),
        "Multi user read requests": () => multiUserReadRequests(10, 10, 10),
        "Multi user Input/Output": () => multiUserInputOutput(10, 10, 10),
    };

    // Execute all tests.
    for (const test in tests) {

        console.log(test + "...");

        // The test will return single or multiple tuples of time periods.
        // Multiple tuples mean that the test had multiple sub-tests inside it.
        // Each tuple indicates [start time, end time] of a particular atomic test.
        const result = await tests[test]();

        // If the result is a single period tuple, put them in a parent array.
        const runPeriods = Array.isArray(result[0]) ? result : [result];

        // Duration is calculated as the duration between earliest start time and latest end time.
        const startTimes = runPeriods.map(p => p[0]);
        const endTimes = runPeriods.map(p => p[1]);
        const minStartTime = Math.min.apply(null, startTimes);
        const maxEndTime = Math.max.apply(null, endTimes);
        const duration = maxEndTime - minStartTime;
        console.log(duration + "ms");
    }

    console.log("Done.");
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

function singleUserReadRequests(payloadKB, requestCount) {

    return new Promise(async resolve => {

        const payload = "A".repeat(payloadKB * 1024);
        let respCount = 0;

        const hpc = await createClient();
        const timer = new Timer();

        hpc.on(HotPocket.events.contractReadResponse, (response) => {
            respCount++;
            if (respCount == requestCount) {
                const runPeriod = timer.stop();
                hpc.close().then(() => resolve(runPeriod));
            }
        });

        timer.start();
        for (let i = 0; i < requestCount; i++) {
            hpc.sendContractReadRequest(payload);
        }
    })
}

function singleUserInputOutput(payloadKB, requestCount) {

    return new Promise(async (resolve) => {

        const payload = "A".repeat(payloadKB * 1024);
        let respCount = 0;

        const hpc = await createClient();
        const timer = new Timer();

        hpc.on(HotPocket.events.contractOutput, (response) => {
            respCount++;
            if (respCount == requestCount) {
                const runPeriod = timer.stop();
                hpc.close().then(() => resolve(runPeriod));
            }
        });

        timer.start();
        for (let i = 0; i < requestCount; i++) {
            const nonce = i.toString().padStart(5);
            await hpc.sendContractInput(payload, nonce, 20);
        }
    })
}

function multiUserReadRequests(payloadKB, requestCountPerUser, userCount) {

    const tasks = [];
    for (let i = 0; i < userCount; i++) {
        tasks.push(singleUserReadRequests(payloadKB, requestCountPerUser));
    }
    return Promise.all(tasks);
}

function multiUserInputOutput(payloadKB, requestCountPerUser, userCount) {

    const tasks = [];
    for (let i = 0; i < userCount; i++) {
        tasks.push(singleUserInputOutput(payloadKB, requestCountPerUser));
    }
    return Promise.all(tasks);
}

function largePayload(payloadMB) {
    return new Promise(async (resolve) => {

        const payload = "A".repeat(payloadMB * 1024 * 1024);

        const hpc = await createClient();
        const timer = new Timer();

        hpc.on(HotPocket.events.contractOutput, (response) => {
            if (response.length < payload.length)
                console.log("Payload length mismatch.");

            const runPeriod = timer.stop();
            hpc.close().then(() => resolve(runPeriod));
        });

        timer.start();
        await hpc.sendContractInput(payload);
    })
}

function Timer() {
    let startedOn = null;

    this.start = () => {
        startedOn = new Date().getTime();
    }

    this.stop = () => {
        const endedOn = new Date().getTime();
        return [startedOn, endedOn];
    }
}

main();