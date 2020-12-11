const fs = require('fs');
const readline = require('readline');
const { exit } = require('process');
const bson = require('bson');
var path = require("path");
const HotPocket = require('./hp-client-lib');

async function main() {

    const keys = await HotPocket.generateKeys();

    const pkhex = Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    let server = 'wss://localhost:8080'
    if (process.argv.length == 3) server = 'wss://localhost:' + process.argv[2]
    if (process.argv.length == 4) server = 'wss://' + process.argv[2] + ':' + process.argv[3]
    const hpc = await HotPocket.createClient(null, null, keys, [server], null, HotPocket.protocols.bson);

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        exit();
    }
    console.log('HotPocket Connected.');

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocket.events.disconnect, () => {
        console.log('Server diconnected');
        exit();
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocket.events.contractOutput, (output) => {
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
    })

    // This will get fired when contract sends a read response.
    hpc.on(HotPocket.events.contractReadResponse, (response) => {
        const result = bson.deserialize(response);
        if (result.type == "downloadResult") {
            if (result.status == "ok") {
                fs.writeFileSync(result.fileName, result.content.buffer);
                console.log("File " + result.fileName + " downloaded to current directory.");
            }
            else {
                console.log("File " + result.fileName + " download failed. reason: " + result.status);
            }
        }
        else {
            console.log("Unknown read request result.");
        }
    })

    // On ctrl + c we should close HP connection gracefully.
    process.once('SIGINT', function () {
        console.log('SIGINT received...');
        hpc.close();
    });

    // start listening for stdin
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    console.log("Ready to accept inputs.");

    const input_pump = () => {
        rl.question('', async (inp) => {

            if (inp.startsWith("upload ")) {

                const filePath = inp.substr(7);
                const fileName = path.basename(filePath)
                const fileContent = fs.readFileSync(filePath);
                const sizeKB = Math.round(fileContent.length / 1024);
                console.log("Uploading file " + fileName + " (" + sizeKB + " KB)");

                const submissionStatus = await hpc.sendContractInput(bson.serialize({
                    type: "upload",
                    fileName: fileName,
                    content: fileContent
                }), null, 100);

                if (submissionStatus && submissionStatus != "ok")
                    console.log("Upload failed. reason: " + submissionStatus);
            }
            else if (inp.startsWith("delete ")) {

                const fileName = inp.substr(7);
                const submissionStatus = await hpc.sendContractInput(bson.serialize({
                    type: "delete",
                    fileName: fileName
                }));

                if (submissionStatus && submissionStatus != "ok")
                    console.log("Delete failed. reason: " + submissionStatus);
            }
            else if (inp.startsWith("download ")) {

                const fileName = inp.substr(9);
                hpc.sendContractReadRequest(bson.serialize({
                    type: "download",
                    fileName: fileName
                }));
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