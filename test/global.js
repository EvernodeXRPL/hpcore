const ws_api = require('ws');

module.exports = {
    init: function(endpoint) {
        wsurl = endpoint;
    },
    testcontext: function (methodname) {

        let ws = new ws_api(wsurl, { rejectUnauthorized: false });

        let timer = setTimeout(() => {
            ws.removeAllListeners();
            ws.close();
            fail(methodname, "Timeout");
        }, 1000);

        let ctx = {
            ws,
            pass: function (message) {
                clearTimeout(timer);
                ws.removeAllListeners();
                ws.close();
                pass(methodname, message);
            },
            fail: function (message) {
                clearTimeout(timer);
                ws.removeAllListeners();
                ws.close();
                fail(methodname, message);
            }
        }

        ws.onerror = function () {
            ctx.fail('Connection error');
        };

        return ctx;
    }
}

let wsurl = '';

function pass(methodname, message) {
    let log = "PASS: " + methodname + (message ? ": " + message : "");
    console.log('\x1b[32m%s\x1b[0m', log)
}

function fail(methodname, message) {
    let log = "FAIL: " + methodname + (message ? ": " + message : "");
    console.log('\x1b[31m%s\x1b[0m', log);
}