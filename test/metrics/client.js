const HotPocket = require('./hp-client-lib');

async function main() {

    const keys = await HotPocket.generateKeys();
    const server = 'wss://' + process.argv[2] + ':' + process.argv[3]

    // Maintain multiple connections with contract id/version and trusted server key validation.
    const hpc = await HotPocket.createClient([server], keys,
        {
            contractId: "5657a933-74e3-4e5a-b1ab-c4de52a86cb3",
            protocol: HotPocket.protocols.json
        });

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        return;
    }
    console.log('HotPocket Connected.');

    const tests = {
        "Read requests": testReadRequests
    };

    for (const test in tests) {
        const start = new Date();

        hpc.clear();
        await tests[test](hpc);

        const end = new Date();
        const duration = end.getTime() - start.getTime();

        console.log(test + " " + duration + "ms");
    }

    await testReadRequests(hpc);
}

function testReadRequests(hpc) {

    return new Promise(resolve => {

        const payload = "ReadReq";
        const requestCount = 100;
        let respCount = 0;

        hpc.on(HotPocket.events.contractReadResponse, (response) => {
            if (response == payload)
                respCount++;

            if (respCount == requestCount)
                resolve();
        });

        for (let i = 0; i < requestCount; i++) {
            hpc.sendContractReadRequest(payload);
        }
    })
}

main();