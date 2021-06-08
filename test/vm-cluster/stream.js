const HotPocket = require('../../examples/js_client/lib/hp-client-lib');
const azure = require('azure-storage');
const fs = require('fs');
const https = require('https')

const reconnectDelayMax = 60000;
const dispatchInterval = 1000;
const stateUploadInterval = 10000;
const metricsTrackInterval = 10000;
const eventsBatchSize = 10;
const tableBatchSize = 20;

let keys = null;
let vultrApiKey = null;
let azureTable = null;
let tableSvc = null;
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

    // Create Azure table service.
    if (!config.azure_table) {
        console.log("Azure table config missing.");
        return;
    }
    tableSvc = azure.createTableServiceWithSas(config.azure_table.host, config.azure_table.sas);
    azureTable = config.azure_table.table;

    // We only consider clusters with stream=true.
    const clusters = config.contracts.filter(c => c.stream == true).map(c => ({
        name: c.name,
        hosts: c.hosts,
        userPort: c.config.user.port
    }));
    console.log(`${clusters.length} clusters found with streaming enabled.`);
    if (clusters.length == 0)
        return;

    // Resolve any vultr hosts.
    await Promise.all(clusters.map(c => resolveHosts(c)));
    if (clusters.filter(c => c.hosts.length > 0).length == 0)
        return;

    // Start node state uploader.
    // This keeps uploading latest node state into table storage.
    nodeStateUploader();

    // Start event dispatcher.
    // This keeps sending events to the ingestion endpoint.
    eventDispatcher();

    // Start event metrics tracker.
    // metricsTracker();

    // Start streaming events from all clusters.
    clusters.forEach(c => streamCluster(c));
}

async function resolveHosts(cluster) {
    // If first host is an element with the pattern "vultr:", then we fetch hosts from vultr.
    if (cluster.hosts.length > 0 && cluster.hosts[0].startsWith("vultr:"))
        cluster.hosts = await getVultrHosts(cluster.hosts[0].split(":")[1]);

    console.log(`${cluster.hosts.length} hosts in '${cluster.name}' cluster.`)
}

function eventDispatcher() {

    // Dispatch all queued events in batches.
    const events = queue.splice(0);

    for (let i = 0, j = events.length; i < j; i += eventsBatchSize) {
        const batch = events.slice(i, i + eventsBatchSize);

        // TODO: Upload batch of events.
    }

    setTimeout(() => eventDispatcher(), dispatchInterval);
}

function nodeStateUploader() {

    const updated = [];

    for (const [uri, node] of Object.entries(nodes)) {
        if (node.hasUpdates) {
            node.hasUpdates = false;
            updated.push(node);
        }
    }

    const ent = azure.TableUtilities.entityGenerator;
    for (let i = 0, j = updated.length; i < j; i += tableBatchSize) {
        const batch = updated.slice(i, i + tableBatchSize);

        const tableBatch = new azure.TableBatch();

        for (const node of batch) {
            tableBatch.insertOrReplaceEntity({
                PartitionKey: ent.String(node.cluster),
                RowKey: ent.String(node.idx.toString()),
                Uri: ent.String(node.uri),
                LastUpdated: ent.DateTime(new Date(node.lastUpdated)),
                InSync: ent.Boolean(node.inSync),
                LastLedger: ent.String(JSON.stringify(node.lastLedger))
            });
        }

        tableSvc.executeBatch(azureTable, tableBatch, (err) => err && console.log(err));
    }

    setTimeout(() => nodeStateUploader(), stateUploadInterval);
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
    const uri = `wss://${host}:${port}`;
    const node = {
        cluster: clusterName,
        idx: nodeIdx,
        uri: uri,
        failureCount: 0,
        lastLedger: null,
        inSync: null,
        lastUpdated: null
    };

    nodes[uri] = node;

    establishClientConnection(node);
}

async function establishClientConnection(node) {

    const hpc = await HotPocket.createClient([node.uri], keys, { connectionTimeoutMs: 2000 });

    hpc.on(HotPocket.events.disconnect, () => {
        onConnectionFail(node);
    });

    // This will get fired when any ledger event occurs (ledger created, sync status change).
    hpc.on(HotPocket.events.ledgerEvent, (ev) => {
        reportEvent(node, ev);
    });

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        onConnectionFail(node);
    }
    else {
        node.failureCount = 0;
        await hpc.subscribe(HotPocket.notificationChannels.ledgerEvent);
    }
}

function onConnectionFail(node) {

    node.failureCount++;

    // Calculate back-off delay.
    let delay = (2000 * node.failureCount);
    if (delay > reconnectDelayMax)
        delay = reconnectDelayMax;

    console.log(`${node.uri} connection failed. Backoff ${delay}ms.`);

    // Report offline event and connect again after a small delay.
    reportEvent(node, { event: "offline" });
    setTimeout(() => establishClientConnection(node), delay);
}

async function reportEvent(node, ev) {

    const ts = new Date().getTime(); // Epoch milliseconds.

    queue.push({
        cluster: node.cluster,
        idx: node.idx,
        uri: node.uri,
        timestamp: ts,
        data: ev
    });

    if (ev.event == 'ledger_created') {
        node.inSync = true;
        node.lastLedger = ev.ledger;
    }
    else if (ev.event == 'sync_status') {
        node.inSync = ev.inSync;
    }
    node.hasUpdates = true;
    node.lastUpdated = ts;

    const count = metrics[node.cluster];
    metrics[node.cluster] = count ? (count + 1) : 1;
}

function getVultrHosts(group) {

    return new Promise(resolve => {

        if (!group || group.trim().length == 0)
            resolve([]);

        const req = https.request({
            hostname: 'api.vultr.com',
            port: 443,
            path: `/v2/instances?tag=${group}`,
            method: 'GET',
            headers: { "Authorization": `Bearer ${vultrApiKey}` }
        }, res => {
            if (res.statusCode >= 200 && res.statusCode < 300)
                res.on('data', d => resolve(JSON.parse(d).instances.map(i => i.main_ip)));
            else
                resolve([]);
        })

        req.on('error', error => {
            console.error(error);
            resolve([]);
        })

        req.end();
    })
}

main();