const HotPocket = require('../../examples/js_client/lib/hp-client-lib');
const fs = require('fs');

const reconnectDelayMax = 60000;
const dispatchInterval = 1000;
const metricsTrackInterval = 10000;
const dispatchBatchSize = 10;

let keys = null;
let vultrApiKey = null;
const queue = [];
const metrics = {};
const nodes = {};

async function main() {

    keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    // Load cluster config.
    const config = JSON.parse(fs.readFileSync("config.json"));
    vultrApiKey = config.vultr.api_key;

    // We only consider clusters with stream=true.
    const clusters = config.contracts.filter(c => c.stream == true).map(c => ({
        name: c.name,
        hosts: c.hosts,
        userPort: c.config.user.port
    }));

    console.log(`${clusters.length} clusters found with streaming enabled.`);
    if (clusters.length == 0)
        return;

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

    cluster.hosts.forEach((h, idx) => streamNode(cluster.name, (idx + 1), h, cluster.userPort));
}

function streamNode(clusterName, nodeIdx, host, port) {
    const serverUri = `wss://${host}:${port}`;
    nodes[serverUri] = {
        failureCount: 0
    };

    establishClientConnection(clusterName, nodeIdx, serverUri);
}

async function establishClientConnection(clusterName, idx, serverUri) {

    const hpc = await HotPocket.createClient([serverUri], keys, { connectionTimeoutMs: 2000 });

    hpc.on(HotPocket.events.disconnect, () => {
        onConnectionFail(clusterName, idx, serverUri);
    });

    // This will get fired when any ledger event occurs (ledger created, sync status change).
    hpc.on(HotPocket.events.ledgerEvent, (ev) => {
        reportEvent(clusterName, idx, serverUri, ev);
    });

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        onConnectionFail(clusterName, idx, serverUri);
    }
    else {
        nodes[serverUri].failureCount = 0;
        await hpc.subscribe(HotPocket.notificationChannels.ledgerEvent);
    }
}

function onConnectionFail(clusterName, idx, serverUri) {

    const node = nodes[serverUri];
    node.failureCount++;

    // Calculate back-off delay.
    let delay = (2000 * node.failureCount);
    if (delay > reconnectDelayMax)
        delay = reconnectDelayMax;

    console.log(`${serverUri} connection failed. Backoff ${delay}ms.`);

    // Report offline event and connect again after a small delay.
    reportEvent(clusterName, idx, serverUri, { event: "offline" });
    setTimeout(() => establishClientConnection(clusterName, idx, serverUri), delay);
}

async function reportEvent(clusterName, nodeIdx, serverUri, ev) {
    const obj = {
        cluster: clusterName,
        idx: nodeIdx,
        uri: serverUri,
        timestamp: new Date().getTime(), // Epoch milliseconds.
        data: ev
    }

    queue.push(obj);

    const count = metrics[clusterName];
    metrics[clusterName] = count ? (count + 1) : 1;
}

main();