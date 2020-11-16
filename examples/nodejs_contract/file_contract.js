const { HotPocketContract } = require("./hp-contract-lib");
const fs = require('fs');
const bson = require('bson');

const fileContract = (ctx) => {
    ctx.users.onMessage(async (user, buf) => {
        const msg = bson.deserialize(buf);

        if (msg.type == "upload") {
            if (fs.existsSync(msg.fileName)) {
                await user.send(bson.serialize({
                    type: "uploadResult",
                    status: "already_exists",
                    fileName: msg.fileName
                }));
            }
            else if (msg.content.length > 10 * 1024 * 1024) { // 10MB
                await user.send(bson.serialize({
                    type: "uploadResult",
                    status: "too_large",
                    fileName: msg.fileName
                }));
            }
            else {

                // Save the file.
                fs.writeFileSync(msg.fileName, msg.content.buffer);

                await user.send(bson.serialize({
                    type: "uploadResult",
                    status: "ok",
                    fileName: msg.fileName
                }));
            }
        }
        else if (msg.type == "delete") {
            if (fs.existsSync(msg.fileName)) {
                fs.unlinkSync(msg.fileName);
                await user.send(bson.serialize({
                    type: "deleteResult",
                    status: "ok",
                    fileName: msg.fileName
                }));
            }
            else {
                await user.send(bson.serialize({
                    type: "deleteResult",
                    status: "not_found",
                    fileName: msg.fileName
                }));
            }
        }
        else if (msg.type == "download") {
            if (fs.existsSync(msg.fileName)) {
                const fileContent = fs.readFileSync(msg.fileName);
                await user.send(bson.serialize({
                    type: "downloadResult",
                    status: "ok",
                    fileName: msg.fileName,
                    content: fileContent
                }));
            }
            else {
                await user.send(bson.serialize({
                    type: "downloadResult",
                    status: "not_found",
                    fileName: msg.fileName
                }));
            }
        }
    });
};

const hpc = new HotPocketContract();
hpc.init(fileContract);
