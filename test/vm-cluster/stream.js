const HotPocket = require('../../examples/js_client/lib/hp-client-lib');
const fs = require('fs');

const reconnectDelay = 1000;
const dispatchInterval = 1000;
const metricsTrackInterval = 10000;
const dispatchBatchSize = 10;

let keys = null;
let vultrApiKey = null;
const queue = [];
const metrics = {};

async function main() {

    keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    // Load cluster config.
    const config = JSON.parse(fs.readFileSync("config.json"));
    vultrApiKey = config.vultr.api_key;
    const clusters = config.contracts.map(c => ({
        name: c.name,
        hosts: c.hosts,
        userPort: c.config.user.port
    }));

    // Start event dispatcher.
    eventDispatcher();

    // Start event metrics tracker.
    // metricsTracker();

    // Start streaming events from all clusters.
    clusters.forEach(c => streamCluster(c));
}

function eventDispatcher() {

    // Dispatch all queued events in batches.
    const events = queue.splice(0);

    var i, j, batch;
    for (i = 0, j = events.length; i < j; i += dispatchBatchSize) {
        batch = events.slice(i, i + dispatchBatchSize);

        // TODO: Upload batch of events.
    }

    setTimeout(() => eventDispatcher(), dispatchInterval);
}

function metricsTracker() {

    for (const [name, count] of Object.entries(metrics)) {
        console.log(`${name}: ${count} events.`);
    }

    setTimeout(() => metricsTracker(), metricsTrackInterval);
}

async function streamCluster(cluster) {
    console.log(`Starting to stream cluster '${cluster.name}'...`);

    // TODO: Resolve Vultr vm groups.

    await Promise.all(cluster.hosts.map((h, idx) => streamNode(cluster.name, (idx + 1), h, cluster.userPort)));
}

async function streamNode(clusterName, nodeIdx, host, port) {
    const serverUri = `wss://${host}:${port}`;
    await establishClientConnection(clusterName, nodeIdx, serverUri);
}

async function establishClientConnection(clusterName, idx, serverUri) {

    const hpc = await HotPocket.createClient([serverUri], keys);

    hpc.on(HotPocket.events.disconnect, () => {
        console.log(serverUri + " disconnected.");
        reportEvent(clusterName, idx, serverUri, { event: "disconnect" })

        // Connect again after a small delay.
        setTimeout(() => establishClientConnection(serverUri), reconnectDelay);
    });

    // This will get fired when any ledger event occurs (ledger created, sync status change).
    hpc.on(HotPocket.events.ledgerEvent, (ev) => {
        reportEvent(clusterName, idx, serverUri, ev);
    })

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed. ' + serverUri);

        // Connect again after a small delay.
        setTimeout(() => establishClientConnection(serverUri), reconnectDelay);
    }
    else {
        await hpc.subscribe(HotPocket.notificationChannels.ledgerEvent);
    }
}

async function reportEvent(clusterName, nodeIdx, serverUri, ev) {
    const obj = {
        cluster: clusterName,
        nodeIdx: nodeIdx,
        serverUri: serverUri,
        epoch: new Date().getTime(), // Epoch milliseconds.
        data: ev
    }

    queue.push(obj);

    const count = metrics[clusterName];
    metrics[clusterName] = count ? (count + 1) : 1;
}

main();