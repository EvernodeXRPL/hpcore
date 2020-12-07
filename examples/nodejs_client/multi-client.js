const { HotPocketClient, HotPocketKeyGenerator, HotPocketEvents } = require('./hp-node-client-lib');

async function main() {

    const clientCount = 3;
    const clients = [];
    for (let i = 1; i <= clientCount; i++) {
        clients.push(new RoboClient('wss://localhost:', 8081, i.toString()));
    }

    await Promise.all(clients.map(c => c.connect()));
    console.log("Clients connected.");

    await Promise.all(clients.map(c => c.sendInputs(["A", "B", "C"])));
    console.log("Clients submitted.");

    // await Promise.all(clients.map(c => c.disconnect()));
    // console.log("Clients closed.");
}

function RoboClient(server, port, clientId) {

    this.connect = async () => {
        this.keys = await HotPocketKeyGenerator.generate();
        this.hpclient = new HotPocketClient(null, server + port, this.keys);


        if (!await this.hpclient.connect()) {
            this.log('Connection failed.');
        }
        this.log('HotPocket Connected.');

        // This will get fired if HP server disconnects unexpectedly.
        this.hpclient.on(HotPocketEvents.disconnect, () => {
            this.log('Server disconnected');
        })

        // This will get fired when contract sends an output.
        this.hpclient.on(HotPocketEvents.contractOutput, (output) => {
            this.log("Contract output>> " + Buffer.from(output, "hex"));
        })

        // This will get fired when contract sends a read response.
        this.hpclient.on(HotPocketEvents.contractReadResponse, (response) => {
            this.log("Contract read response>> " + Buffer.from(response, "hex"));
        })
    }

    this.disconnect = async () => {
        await this.hpclient.close();
    }

    this.sendInputs = async (inputs) => {

        let idx = 1;
        let tasks = [];
        inputs.forEach(inp => {
            const nonce = clientId.toString() + '-' + idx.toString();
            tasks.push(this.hpclient.sendContractInput((clientId + inp), nonce).then(submissionStatus => {
                if (submissionStatus && submissionStatus != "ok")
                    this.log("Input submission failed. reason: " + submissionStatus);
            }));
            idx++;
        })
        await Promise.all(tasks);
    }

    this.log = (text) => {
        console.log(clientId + ": " + text)
    }
}

main();