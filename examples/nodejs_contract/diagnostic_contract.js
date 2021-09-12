const HotPocket = require("./hp-contract-lib");
const fs = require('fs').promises;
var seedrandom = require('seedrandom');

const filename = "file.dat";
const autofilePrefix = "autofile";
const autofileSize = 1 * 1024 * 1024;

const diagnosticContract = async (ctx) => {

    // Collection of per-user promises to wait for. Each promise completes when inputs for that user is processed.
    const userHandlers = [];

    for (const user of ctx.users.list()) {

        // For each user we add a promise to list of promises.
        userHandlers.push(new Promise(async (resolve) => {

            // The contract need to ensure that all outputs for a particular user is emitted
            // in deterministic order. Hence, we are processing all inputs for each user sequentially.
            for (const input of user.inputs) {

                const buf = await ctx.users.read(input);
                const parts = buf.toString().split(" ");
                const mode = parts[0];
                const data = parts[1];
                let output = null;

                if (mode === "status") {
                    output = "Hot Pocket diagnostic contract is running.";
                }
                else if (mode === "file") {
                    const param = parseInt(data);
                    const stat = await fs.stat(filename).catch(() => { });

                    if (isNaN(param)) {
                        if (!stat)
                            output = "File does not exist.";
                        else
                            output = "Current size: " + stat.size / (1024 * 1024) + " MB";
                    }
                    else {
                        if (param == 0) {
                            if (stat) {
                                await fs.unlink(filename);
                                output = "Deleted file.";
                            }
                        }
                        else {
                            if (!stat)
                                await fs.writeFile(filename, "Initial");

                            await fs.truncate(filename, param * 1024 * 1024);
                            output = "Updated file size to " + param + " MB";
                        }
                    }
                }
                else if (mode === "files") {
                    const param = parseInt(data);
                    const autofiles = await (await fs.readdir(".")).filter(f => f.startsWith(autofilePrefix));

                    if (isNaN(param)) {
                        output = autofiles.length + " autofiles found.";
                    }
                    else {
                        if (param == 0) {
                            for (file of autofiles) {
                                await fs.unlink(file);
                            }
                            output = autofiles.length + " autofiles deleted.";
                        }
                        else {
                            const content = "A".repeat(autofileSize);
                            for (let i = (autofiles.length + 1); i <= (autofiles.length + param); i++) {
                                await fs.writeFile(autofilePrefix + i, content);
                            }
                            output = param + " new autofiles created. Total: " + (autofiles.length + param);
                        }
                    }
                }
                else if (mode === "download") {
                    const param = parseFloat(data);
                    if (!isNaN(param)) {
                        output = "A".repeat(param * 1024 * 1024);
                    }
                }
                else if (mode === "roundtime") {
                    const param = parseInt(data);
                    if (!isNaN(param)) {
                        if (param >= 100) {
                            const config = await ctx.getConfig();
                            config.roundtime = param;
                            await ctx.updateConfig(config)
                            output = "Updated Roundtime to " + config.roundtime;
                        }
                    }
                    else {
                        const config = await ctx.getConfig();
                        output = "Roundtime: " + config.roundtime;
                    }
                }
                else {
                    output = "Received unrecognized input of length " + buf.length;
                }

                if (output)
                    await user.send(output);
            }

            // The promise gets completed when all inputs for this user are processed.
            resolve();
        }));
    }

    // Wait until all user promises are complete.
    await Promise.all(userHandlers);

    // Modify random file bytes (if file exists)
    {
        const stat = await fs.stat(filename).catch(() => { });
        if (stat) {
            const rng = seedrandom(ctx.lcl_hash);
            const fh = await fs.open(filename, 'r+');

            for (let i = 0; i < 3; i++) {
                const pos = rng() * (stat.size - 50);
                const buf = ctx.lcl_hash.substr(i * 10, 10);
                await fh.write(buf, pos);
            }

            await fh.close();
        }
    }

}

const hpc = new HotPocket.Contract();
hpc.init(diagnosticContract);