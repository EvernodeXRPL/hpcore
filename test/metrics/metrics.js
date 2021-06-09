// HotPocket test client to collect metrics.
// This assumes the HotPocket server we are connecting to is hosting the echo contract.

const HotPocket = require('../../examples/js_client/lib/hp-client-lib');

let server = 'wss://localhost:8080';
if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2];
if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3];
console.log("Server: " + server);

let activity = {};

async function main() {

    HotPocket.setLogLevel(1);

    const tests = {
        "Large payload": () => largePayload(2),
        "Single user read requests": () => multiUserReadRequests(10, 10, 1),
        "Single user Input/Output": () => multiUserInputOutput(10, 10, 1),
        "Multi user read requests": () => multiUserReadRequests(10, 10, 10),
        "Multi user Input/Output": () => multiUserInputOutput(10, 10, 10),
    };

    activityLogger();

    // Execute all tests.
    for (const test in tests) {

        console.log();
        console.log(test + "...");

        // The test will return single or multiple tuples of time periods.
        // Multiple tuples mean that the test had multiple sub-tests inside it.
        // Each tuple indicates [start time, end time] of a particular atomic test.
        const result = await tests[test]();

        // Test ended. Clear activity.
        activity = {};

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

    activity = null;
    console.log("Done.");
}

async function activityLogger() {
    if (activity && Object.keys(activity).length > 0)
        console.log(JSON.stringify(activity));

    if (activity)
        setTimeout(() => activityLogger(), 1000);
}

async function createClient() {
    increment("creating");
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
    decrement("creating");
    increment("clients");

    return hpc;
}

function singleUserReadRequests(payloadKB, requestCount) {

    return new Promise(async resolve => {

        const payload = "A".repeat(payloadKB * 1024);
        let respCount = 0;

        const hpc = await createClient();
        const timer = new Timer();

        hpc.on(HotPocket.events.contractReadResponse, (response) => {
            increment("readresp");
            respCount++;
            if (respCount == requestCount) {
                const runPeriod = timer.stop();
                hpc.close().then(() => resolve(runPeriod));
            }
        });

        timer.start();
        for (let i = 0; i < requestCount; i++) {
            increment("submitting");
            hpc.sendContractReadRequest(payload).then(() => {
                decrement("submitting");
                increment("submitted");
            });
        }
    })
}

function singleUserInputOutput(payloadKB, requestCount) {
    return new Promise(async (resolve) => {

        const payload = "A".repeat(payloadKB * 1024);
        let respCount = 0;

        const hpc = await createClient();
        const timer = new Timer();

        hpc.on(HotPocket.events.contractOutput, (r) => {
            r.outputs.forEach(response => {
                increment("outputs");
                respCount++;
                if (respCount == requestCount) {
                    const runPeriod = timer.stop();
                    hpc.close().then(() => resolve(runPeriod));
                }
            });
        });

        timer.start();
        for (let i = 0; i < requestCount; i++) {
            increment("submitting");
            const input = await hpc.submitContractInput(payload);
            decrement("submitting");
            increment("submitted");
            input.submissionStatus.then(onStatusResponse);
        }
    })
}

function multiUserReadRequests(payloadKB, requestCountPerUser, userCount) {

    console.log("Submitting " + (requestCountPerUser * userCount) + " requests.");

    const tasks = [];
    for (let i = 0; i < userCount; i++) {
        tasks.push(singleUserReadRequests(payloadKB, requestCountPerUser));
    }
    return Promise.all(tasks);
}

function multiUserInputOutput(payloadKB, requestCountPerUser, userCount) {

    console.log("Submitting " + (requestCountPerUser * userCount) + " requests.");

    const tasks = [];
    for (let i = 0; i < userCount; i++) {
        tasks.push(singleUserInputOutput(payloadKB, requestCountPerUser));
    }
    return Promise.all(tasks);
}

function largePayload(payloadMB) {
    console.log("Submitting " + payloadMB + " MB request.")
    return new Promise(async (resolve) => {

        const payload = "A".repeat(payloadMB * 1024 * 1024);

        const hpc = await createClient();
        const timer = new Timer();

        hpc.on(HotPocket.events.contractOutput, (r) => {
            r.outputs.forEach(response => {
                increment("outputs");
                if (response.length < payload.length)
                    console.log("Payload length mismatch.");

                const runPeriod = timer.stop();
                hpc.close().then(() => resolve(runPeriod));
            })
        });

        timer.start();
        increment("submitting");
        const input = await hpc.submitContractInput(payload);
        decrement("submitting");
        increment("submitted");
        input.submissionStatus.then(onStatusResponse);
    })
}

function increment(key) {
    if (!activity[key])
        activity[key] = 0;
    activity[key]++;
}

function decrement(key) {
    activity[key]--;
    if (activity[key] == 0)
        delete activity[key];
}

function onStatusResponse(s) {

    increment("statresp");

    if (!activity.groups)
        activity.groups = {};

    if (!activity.groups[s.status])
        activity.groups[s.status] = 0;

    activity.groups[s.status]++;

    if (s.status != "accepted")
        console.log(s.reason);
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