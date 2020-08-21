const fs = require('fs');

function HotPocketContract() {
    const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
    this.readonly = hpargs.readonly;
    this.timestamp = hpargs.ts;

    if (!this.readonly) {
        const lclParts = hpargs.lcl.split("-");
        this.lcl = {
            seqNo: parseInt(lclParts[0]),
            hash: lclParts[1]
        };

        this.npl = new HotPocketNplChannel(hpargs.nplfd[0], hpargs.nplfd[1]);
    }

    this.users = {};
    Object.keys(hpargs.usrfd).forEach((userPubKey) => {
        const userfds = hpargs.usrfd[userPubKey];
        this.users[userPubKey] = new HotPocketChannel(userfds[0], userfds[1]);
    });
}

function HotPocketChannel(infd, outfd) {
    this.readInput = function () {
        return new Promise((resolve) => {
            if (infd == -1) {
                resolve(null);
            }
            else {
                const s = fs.createReadStream(null, { fd: infd });
                drainStream(s).then(buf => resolve(buf));
            }
        });
    }

    this.sendOutput = function (output) {
        fs.writeFileSync(outfd, output);
    }

    const drainStream = function (stream) {

        return new Promise((resolve) => {

            const dataParts = [];

            const resolveBuffer = function () {
                if (dataParts.length > 0)
                    return resolve(Buffer.concat(dataParts));
                else
                    return resolve(null);
            }

            stream.on("data", d => {
                dataParts.push(d);
            });
            stream.on('end', resolveBuffer);
            stream.on("close", resolveBuffer);
            stream.on("error", () => {
                resolve(null);
            });
        });
    }
}

function HotPocketNplChannel(infd, outfd) {
    this.readInput = function () {
        if (infd == -1)
            return null;

        // Input may consist of multiple messages.
        // Each message has the format:
        // | NPL version (1 byte) | reserve (1 byte) | msg length (2 bytes BE) | peer pubkey (32 bytes) | msg |

        const inputs = []; // Peer inputs will be populated to this.

        const buf = fs.readFileSync(infd);
        let pos = 0;
        while (pos < buf.byteLength) {

            pos += 2; // Skip version and reserve.

            // Read message len.
            const msgLenBuf = readBytes(buf, pos, 2);
            if (!msgLenBuf) break;
            const msgLen = msgLenBuf.readUInt16BE();

            pos += 2;
            const pubKeyBuf = readBytes(buf, pos, 32);
            if (!pubKeyBuf) break;

            pos += 32;

            const msgBuf = readBytes(buf, pos, msgLen)
            if (!msgBuf) break;

            inputs.push({
                pubkey: pubKeyBuf.toString("hex"),
                input: msgBuf
            });

            pos += msgLen;
        }

        return inputs;
    }

    this.sendOutput = function (output) {
        fs.writeFileSync(outfd, output);
    }

    const readBytes = function (buf, pos, count) {
        if (pos + count > buf.byteLength)
            return null;
        return buf.slice(pos, pos + count);
    }
}

module.exports = {
    HotPocketContract
}