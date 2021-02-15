const HotPocket = require("./hp-contract-lib");
const fs = require('fs');

// HP smart contract is defined as a function which takes HP ExecutionContext as an argument.
// HP considers execution as complete, when this function completes and all the NPL message callbacks are complete.
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

    // Get list of all unl nodes in the cluster.
    // ctx.unl.list();

    // Get the unl node identified by public key.
    // ctx.unl.find("<PubkeyHex>");

    // NPL messages example.
    // if (!ctx.readonly) {
    //     ctx.unl.onMessage((node, msg) => {
    //         console.log(msg + " from " + node.pubKey);
    //     })
    //     await ctx.unl.send("Hello");
    // }

    // Update patch config
    // const config = await ctx.getConfig();
    // config.unl.push("edf3f3bff36e22d0e1c7abf791ca4900e717754443b8e861dcfbf1cd2bbd0f6159");
    // await ctx.updateConfig(config);
}

const hpc = new HotPocket.Contract();
hpc.init(echoContract);