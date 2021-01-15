const HotPocket = require("./hp-contract-lib");
const fs = require('fs');

// HP smart contract is defined as a function which takes HP ExecutionContext as an argument.
// HP considers execution as complete, when this function completes and all the NPL message callbacks are complete.
const echoContract = async (ctx) => {

    if (!ctx.readonly) {
        const jsonObj = {
            "version": "1.0",
            "unl": [
                "ed6f985e39f17914b3fc6958594b92e5998d12c0299ac9eee734eaddac7a890cf0",
                "ed5eef63e0e48798b792f361803f722a373ba7b93363ab4009191633919f894052",
                "ed0bb1a736ef1321746ff835f7e54a28bfe10d537199a60b31033514afde368fd6",
                "ed5440b242e981c5fff677cf5ff737265715320625354692f2f1f56287b79fae3f",
                "ed32fa6b8e5667aaa8793b733313787513c72ca4025b35c16f913f28fee2dfe365"
            ],
            "bin_path": "/usr/local/bin/node",
            "bin_args": "/contract/bin/echo_contract.js",
            "roundtime": 1000,
            "consensus": "private",
            "npl": "private",
            "appbill": {
              "mode": "",
              "bin_args": ""
            }
          };
        fs.appendFileSync("exects.txt", "ts:" + ctx.timestamp + "\n");
        fs.writeFileSync("../patch.cfg", JSON.stringify(jsonObj));
    }


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
}

const hpc = new HotPocket.Contract();
hpc.init(echoContract);
