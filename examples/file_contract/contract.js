const fs = require('fs');
const bson = require('bson');

//console.log("===File contract started===");

const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
//console.log("Contract args received from hp: " + hpargs);

Object.keys(hpargs.usrfd).forEach(function (key) {
    const userfds = hpargs.usrfd[key];

    if (userfds[0] != -1) {

        const msg = bson.deserialize(fs.readFileSync(userfds[0]));

        if (msg.type == "upload") {
            if (msg.content.length <= 10 * 1024 * 1024) { // 10MB
                fs.writeFileSync(msg.fileName, msg.content);
                fs.writeSync(userfds[1], bson.serialize({
                    type: "uploadResult",
                    status: "ok",
                    fileName: msg.fileName
                }));
            }
            else {
                fs.writeSync(userfds[1], bson.serialize({
                    type: "uploadResult",
                    status: "too_large",
                    fileName: msg.fileName
                }));
            }
        }
        else if (msg.type == "delete") {
            if (fs.existsSync(msg.fileName)) {
                fs.unlinkSync(msg.fileName);
                fs.writeSync(userfds[1], bson.serialize({
                    type: "deleteResult",
                    status: "ok",
                    fileName: msg.fileName
                }));
            }
            else {
                fs.writeSync(userfds[1], bson.serialize({
                    type: "deleteResult",
                    status: "not_found",
                    fileName: msg.fileName
                }));
            }
        }
        else if (msg.type == "download") {
            if (fs.existsSync(msg.fileName)) {
                const fileContent = fs.readFileSync(msg.fileName);
                fs.writeSync(userfds[1], bson.serialize({
                    type: "downloadResult",
                    status: "ok",
                    fileName: msg.fileName,
                    content: fileContent
                }));
            }
            else {
                fs.writeSync(userfds[1], bson.serialize({
                    type: "downloadResult",
                    status: "not_found",
                    fileName: msg.fileName
                }));
            }
        }
    }
});

//console.log("===File contract ended===");