const fs = require('fs');
const readline = require('readline');
const sodium = require('libsodium-wrappers');
const { exit } = require('process');
const { HotPocketClient, HotPocketProtocols, HotPocketEvents } = require('./hp-client-lib');
const bson = require('bson');
var path = require("path");

async function main() {

    await sodium.ready;

    let keys = {};
    const key_file = '.hp_client_keys';
    if (!fs.existsSync(key_file)) {
        keys = sodium.crypto_sign_keypair();
        keys.privateKey = sodium.to_hex(keys.privateKey)
        keys.publicKey = sodium.to_hex(keys.publicKey)
        fs.writeFileSync(key_file, JSON.stringify(keys))
    } else {
        keys = JSON.parse(fs.readFileSync(key_file))
        keys.privateKey = Uint8Array.from(Buffer.from(keys.privateKey, 'hex'))
        keys.publicKey = Uint8Array.from(Buffer.from(keys.publicKey, 'hex'))
    }

    const pkhex = 'ed' + Buffer.from(keys.publicKey).toString('hex');
    console.log('My public key is: ' + pkhex);

    const hpc = new HotPocketClient("wss://localhost:8080", HotPocketProtocols.BSON, keys);

    // Establish HotPocket connection.
    if (!await hpc.connect()) {
        console.log('Connection failed.');
        exit;
    }
    console.log('HotPocket Connected.');

    // This will get fired if HP server disconnects unexpectedly.
    hpc.on(HotPocketEvents.disconnect, () => {
        console.log('Server diconnected');
        exit;
    })

    // This will get fired when contract sends an output.
    hpc.on(HotPocketEvents.contractOutput, (output) => {
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
    hpc.on(HotPocketEvents.contractReadResponse, (response) => {
        const result = bson.deserialize(response);
        if (result.type == "downloadResult") {
            if (result.status == "ok") {
                fs.writeFileSync(result.fileName, result.content);
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