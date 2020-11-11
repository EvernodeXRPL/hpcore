const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');
const bson = require('bson');

const hpc = new HotPocketContract();

//console.log("===File contract started===");

hpc.events.on("user_message", async (pubKey, input) => {
    const user = hpc.users[pubKey];
    const msg = bson.deserialize(input);
    handlerUserMessage(user, msg);
});

hpc.events.on("all_users_completed", () => {
    hpc.terminate();
});

// Developer should call run method after all the event subscriptions are done.
hpc.run();

const handlerUserMessage = (user, msg) => {

    if (msg.type == "upload") {
        if (fs.existsSync(msg.fileName)) {
            user.sendOutput(bson.serialize({
                type: "uploadResult",
                status: "already_exists",
                fileName: msg.fileName
            }));
        }
        else if (msg.content.length > 10 * 1024 * 1024) { // 10MB
            user.sendOutput(bson.serialize({
                type: "uploadResult",
                status: "too_large",
                fileName: msg.fileName
            }));
        }
        else {

            // Save the file.
            fs.writeFileSync(msg.fileName, msg.content.buffer);

            user.sendOutput(bson.serialize({
                type: "uploadResult",
                status: "ok",
                fileName: msg.fileName
            }));
        }
    }
    else if (msg.type == "delete") {
        if (fs.existsSync(msg.fileName)) {
            fs.unlinkSync(msg.fileName);
            user.sendOutput(bson.serialize({
                type: "deleteResult",
                status: "ok",
                fileName: msg.fileName
            }));
        }
        else {
            user.sendOutput(bson.serialize({
                type: "deleteResult",
                status: "not_found",
                fileName: msg.fileName
            }));
        }
    }
    else if (msg.type == "download") {
        if (fs.existsSync(msg.fileName)) {
            const fileContent = fs.readFileSync(msg.fileName);
            user.sendOutput(bson.serialize({
                type: "downloadResult",
                status: "ok",
                fileName: msg.fileName,
                content: fileContent
            }));
        }
        else {
            user.sendOutput(bson.serialize({
                type: "downloadResult",
                status: "not_found",
                fileName: msg.fileName
            }));
        }
    }
}

//console.log("===File contract ended===");