const fs = require('fs');
const readline = require('readline');
const bson = require('bson');
var path = require("path");
const HotPocket = require('hotpocket-js-client');

async function main() {

    const keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    let server = 'wss://localhost:8080'
    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]
    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]
    const hpc = await HotPocket.createClient([server], keys, { protocol: HotPocket.protocols.bson });

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        return;
    }
    console.log('HotPocket Connected.');

    // start listening for stdin
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    // On ctrl + c we should close HP connection gracefully.
    rl.on('SIGINT', () => {
        console.log('SIGINT received...');
        rl.close();
        hpc.close();
    });

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocket.events.disconnect, () => {
        console.log('Disconnected');
        rl.close();
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocket.events.contractOutput, (r) => {

        r.outputs.forEach(output => {

            const result = bson.deserialize(output);
            if (result.type == "uploadResult") {
                if (result.status == "ok")
                    console.log("File " + result.fileName + " uploaded successfully.");
                else
                    console.log("File " + result.fileName + " upload failed. reason: " + result.status);
            }
            else if (result.type == "deleteResult") {
                if (result.status == "ok")
                    console.log("File " + result.fileName + " deleted successfully.");
                else
                    console.log("File " + result.fileName + " delete failed. reason: " + result.status);
            }
            else {
                console.log("Unknown contract output.");
            }

        });
    })


    console.log("Ready to accept inputs.");

    const input_pump = () => {
        rl.question('', async (inp) => {

            if (inp.startsWith("upload ")) {

                const filePath = inp.substr(7);
                const fileName = path.basename(filePath)
                const fileContent = fs.readFileSync(filePath);
                const sizeKB = Math.round(fileContent.length / 1024);
                console.log("Uploading file " + fileName + " (" + sizeKB + " KB)");

                const input = await hpc.submitContractInput(bson.serialize({
                    type: "upload",
                    fileName: fileName,
                    content: fileContent
                }));

                const submission = await input.submissionStatus;
                if (submission.status != "accepted")
                    console.log("Upload failed. reason: " + submission.reason);
            }
            else if (inp.startsWith("delete ")) {

                const fileName = inp.substr(7);
                const input = await hpc.submitContractInput(bson.serialize({
                    type: "delete",
                    fileName: fileName
                }));

                const submission = await input.submissionStatus;
                if (submission.status != "accepted")
                    console.log("Delete failed. reason: " + submission.reason);
            }
            else if (inp.startsWith("download ")) {

                const fileName = inp.substr(9);
                hpc.submitContractReadRequest(bson.serialize({
                    type: "download",
                    fileName: fileName
                })).then(reply => {
                    const res = bson.deserialize(reply);
                    if (res && res.type === 'downloadResult' && res.status === 'ok')
                        console.log(res.content);
                    else
                        console.log(res);
                });
            }
            else {
                console.log("Invalid command. [upload <local path> | delete <filename> | download <filename>] expected.")
            }

            input_pump();
        })
    }
    input_pump();
}

main();