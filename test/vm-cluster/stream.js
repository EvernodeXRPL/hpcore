const HotPocket = require('../../examples/js_client/lib/hp-client-lib');
const azure = require('azure-storage');
const fs = require('fs').promises;
const https = require('https');
const fetch = require('node-fetch');

const dispatchInterval = process.env.DISPATCH || 1000;
const stateUploadInterval = process.env.STATEUPLOAD || 10000;
const metricsTrackInterval = process.env.METRICSTRACK || 10000;
const backoffDelayMax = process.env.BACKOFFMAX || 60000;
const eventsBatchSize = process.env.EVENTBATCH || 20;
const stateBatchSize = process.env.STATEBATCH || 20;
const synclog = process.env.SYNCLOG || "off";
const healthlog = process.env.HEALTHLOG || "off";

let keys = null;
let vultrApiKey = null;
let azureTable = null;
let tableSvc = null;
const clusterQueues = {};
const metrics = {};
const nodeGroups = {};

async function main() {

    keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    // Load cluster config.
    const config = JSON.parse(await fs.readFile("config.json"));
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
    eventDispatcher(config.azure_function.host, config.azure_function.path);

    // Start event metrics tracker.
    // metricsTracker();

    // Start streaming events from all clusters.
    clusters.forEach(c => streamCluster(c));
}

async function resolveHosts(cluster) {

    // If a host has the pattern "vultr:", then we fetch hosts from vultr.

    const resolvedHosts = [];
    for (const host of cluster.hosts) {
        if (host.startsWith("vultr:"))
            resolvedHosts.push(...await getVultrHosts(host.split(":")[1]));
        else
            resolvedHosts.push(host);
    }

    cluster.hosts = resolvedHosts;
    console.log(`${cluster.hosts.length} hosts in '${cluster.name}' cluster.`)
}

function eventDispatcher(hostname, path) {
    // Dispatch all queued events in batches.
    while (true) {
        obj = {};
        for (const [cluster, data] of Object.entries(clusterQueues)) {
            if (data.length > eventsBatchSize) {
                obj[cluster] = data.splice(0, eventsBatchSize);
            }
            else if (data.length > 0) {
                obj[cluster] = data.splice(0);
            }
        }
        // Break the loop if there is no event data remaining.
        if (Object.keys(obj).length == 0)
            break;

        const data = JSON.stringify(obj);
        const req = https.request({
            hostname: hostname,
            port: 443,
            path: path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        });

        req.on('error', error => {
            console.error(error);
        })

        req.write(data);
        req.end();
    }

    setTimeout(() => eventDispatcher(hostname, path), dispatchInterval);
}

function nodeStateUploader() {


    for (const [cluster, nodes] of Object.entries(nodeGroups)) {

        // Collect nodes with updates inside this cluster.
        const updated = [];
        for (const node of nodes.filter(n => n.hasUpdates)) {
            node.hasUpdates = false;
            updated.push(node);
        }

        const ent = azure.TableUtilities.entityGenerator;
        for (let i = 0, j = updated.length; i < j; i += stateBatchSize) {
            const batch = updated.slice(i, i + stateBatchSize);
            const tableBatch = new azure.TableBatch();

            for (const node of batch) {
                tableBatch.insertOrReplaceEntity({
                    PartitionKey: ent.String(node.cluster),
                    RowKey: ent.String(node.idx.toString()),
                    Uri: ent.String(node.uri),
                    LastUpdated: ent.DateTime(new Date(node.lastUpdated)),
                    Status: ent.String(node.status),
                    LastLedger: ent.String(JSON.stringify(node.lastLedger))
                });
            }

            tableSvc.executeBatch(azureTable, tableBatch, (err) => err && console.log(err));
        }
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
        status: null,
        lastUpdated: null
    };

    if (!nodeGroups[clusterName])
        nodeGroups[clusterName] = [];

    nodeGroups[clusterName].push(node);

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

    // This will get fired when any diagnostic health event occurs.
    if (healthlog === "on") {
        hpc.on(HotPocket.events.healthEvent, async (ev) => {

            const now = new Date().toUTCString();
            if (ev.event === "proposal") {
                delete ev.event;
                const str = JSON.stringify(ev);
                await fs.appendFile("prop_health.log", `${now}, Node${node.idx}, ${node.uri}, ${node.status}, ${str}\n`);
            }
            else if (ev.event === "connectivity") {
                delete ev.event;
                const str = JSON.stringify(ev);
                await fs.appendFile("conn_health.log", `${now}, Node${node.idx}, ${node.uri}, ${node.status}, ${str}\n`);
            }
        });

        await hpc.subscribe(HotPocket.notificationChannels.healthEvent);
    }

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        onConnectionFail(node);
    }
    else {

        const stat = await hpc.getStatus();
        const lastLedger = await hpc.getLedgerBySeqNo(stat.ledgerSeqNo);

        node.failureCount = 0;
        reportEvent(node, { event: "online", ledger: lastLedger, voteStatus: stat.voteStatus });
        await hpc.subscribe(HotPocket.notificationChannels.ledgerEvent);
    }
}

function onConnectionFail(node) {

    node.failureCount++;

    // Calculate back-off delay.
    let delay = (2000 * node.failureCount);
    if (delay > backoffDelayMax)
        delay = backoffDelayMax;

    console.log(`${node.uri} connection failed. Backoff ${delay}ms.`);

    // Report offline event and connect again after a small delay.
    reportEvent(node, { event: "offline" });
    setTimeout(() => establishClientConnection(node), delay);
}

async function reportEvent(node, ev) {

    const ts = new Date().getTime(); // Epoch milliseconds.

    if (!clusterQueues[node.cluster])
        clusterQueues[node.cluster] = [];

    clusterQueues[node.cluster].push({
        cluster: node.cluster,
        idx: node.idx,
        uri: node.uri,
        timestamp: ts,
        data: ev
    });

    if (ev.event == 'ledger_created') {
        node.status = 'in_sync';
        node.lastLedger = ev.ledger;
    }
    else if (ev.event == 'vote_status') {
        // ev.voteStatus - possible values: 'unreliable', 'desync', 'synced'
        node.status = ev.voteStatus == 'desync' ? 'desync' : 'in_sync';

        if (synclog == "on")
            await fs.appendFile("sync_ops.log", `${new Date(ts).toUTCString()}, Node${node.idx}, ${node.uri}, ${ev.voteStatus}, at ${node.lastLedger.seqNo}\n`);
    }
    else if (ev.event == 'online') {
        node.status = ev.voteStatus == 'desync' ? 'desync' : 'in_sync';
        node.lastLedger = ev.ledger;
    }
    else if (ev.event == 'offline') {
        node.status = 'offline';
    }

    node.hasUpdates = true;
    node.lastUpdated = ts;

    const count = metrics[node.cluster];
    metrics[node.cluster] = count ? (count + 1) : 1;
}

function getVultrHosts(group) {

    return new Promise(async (resolve) => {

        if (!group || group.trim().length == 0)
            resolve([]);

        const resp = await fetch(`https://api.vultr.com/v2/instances?tag=${group}`, {
            method: 'GET',
            headers: { "Authorization": `Bearer ${vultrApiKey}` }
        });

        const vms = (await resp.json()).instances;
        if (!vms) {
            console.log("Failed to get vultr instances.");
            resolve([]);
            return;
        }

        const ips = vms.sort((a, b) => (a.label < b.label) ? -1 : 1).map(i => i.main_ip);
        resolve(ips);
    })
}

main();