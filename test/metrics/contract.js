const HotPocket = require("./hp-contract-lib");

const echoContract = async (ctx) => {

    // Collection of user input handler promises to wait for.
    const inputHandlers = [];

    for (const user of ctx.users.list()) {

        for (const input of user.inputs) {

            inputHandlers.push(new Promise(async (resolve) => {
                const buf = await ctx.users.read(input);
                await user.send(buf);
                resolve();
            }));
        }
    }
    await Promise.all(inputHandlers);
}

const hpc = new HotPocket.Contract();
hpc.init(echoContract);