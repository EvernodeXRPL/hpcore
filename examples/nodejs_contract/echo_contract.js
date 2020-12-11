const HotPocket = require("./hp-contract-lib");
const fs = require('fs');

// HP smart contract is defined as a function which takes HP ExecutionContext as an argument.
// HP considers execution as complete, when this function completes and all the peer message callbacks are complete.
const echoContract = async (ctx) => {

    // We just save execution timestamp as an example state file change.
    if (!ctx.readonly)
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");

    // Collection of user input handler promises to wait for.
    const inputHandlers = [];

    for (const user of ctx.users.list()) {

        // This user's pubkey can be accessed from 'user.pubKey'

        for (const input of user.inputs) {

            inputHandlers.push(new Promise(async (resolve) => {

                const buf = await ctx.users.read(input);
                const msg = buf.toString();

                const output = (msg == "ts") ? fs.readFileSync("exects.txt").toString() : ("Echoing: " + msg);
                await user.send(output);

                resolve();
            }));
        }
    }
    await Promise.all(inputHandlers);

    // Get the user identified by public key.
    // ctx.users.find("<PubkeyHex>");

    // Get list of all peers in the cluster.
    // ctx.peers.list();

    // Get the peer identified by public key.
    // ctx.peers.find("<PubkeyHex>");

    // Peer messages example.
    // if (!ctx.readonly) {
    //     ctx.peers.onMessage((peer, msg) => {
    //         console.log(msg + " from " + peer.pubKey);
    //     })
    //     await ctx.peers.send("Hello");
    // }
}

const hpc = new HotPocket.Contract();
hpc.init(echoContract);