const fs = require('fs');

function HotPocketContract() {
    const hpargs = JSON.parse(fs.readFileSync(0, 'utf8'));
    this.readonly = hpargs.readonly;
    this.timestamp = hpargs.ts;
    this.users = {};

    Object.keys(hpargs.usrfd).forEach((userPubKey) => {
        const userfds = hpargs.usrfd[userPubKey];
        this.users[userPubKey] = new HotPocketChannel(userfds[0], userfds[1]);
    });
}

function HotPocketChannel(infd, outfd) {
    this.readInput = function () {
        return infd == -1 ? null : fs.readFileSync(infd);
    }

    this.sendOutput = function (output) {
        fs.writeFileSync(outfd, output);
    }
}

module.exports = {
    HotPocketContract
}