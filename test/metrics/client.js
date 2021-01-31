const HotPocket = require('./hp-client-lib');

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
    const server = 'wss://' + process.argv[2] + ':' + process.argv[3]

    const hpc = await HotPocket.createClient([server], keys,
        {
            contractId: "5657a933-74e3-4e5a-b1ab-c4de52a86cb3",
            protocol: HotPocket.protocols.json
        });

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        return null;
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