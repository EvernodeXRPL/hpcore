const sodium = require('libsodium-wrappers')
const global = require('./global')

module.exports = {
    run: function () {
        sodium.ready.then(() =>
            testmethods.forEach(f => f()));
    }
}

let testmethods = [
    () => {

        let ctx = global.testcontext("challenge: format_is_correct");

        ctx.ws.on('message', (m) => {

            let obj = {};
            try {
                obj = JSON.parse(m);
            } catch {
                ctx.fail('JSON parse failed');
                return;
            }

            if (obj.version && obj.type == 'public_challenge' && obj.challenge)
                ctx.pass();
            else
                ctx.fail('Invalid fields');
        });
    },

    () => {

        let ctx = global.testcontext("challenge: accepts_connection_for_valid_signature");

        ctx.ws.on('message', (m) => {
            let obj = JSON.parse(m);
            var keys = sodium.crypto_sign_keypair();

            // sign the challenge and send back the response
            var sigbytes = sodium.crypto_sign_detached(obj.challenge, keys.privateKey);
            ctx.ws.send(JSON.stringify({
                type: 'challenge_resp',
                challenge: obj.challenge,
                sig: Buffer.from(sigbytes).toString('hex'),
                pubkey: 'ed' + Buffer.from(keys.publicKey).toString('hex')
            }));

            let timer = setTimeout(() => {
                // Wait 500ms and pass. That means we haven't been disconnected thus far.
                ctx.pass();
            }, 500);

            ctx.ws.on('close', () => {
                // Clear the pass timer and fail test if we get disconnected.
                clearTimeout(timer);
                ctx.fail('Got disconnected');
            });
        });
    },

    () => {

        let ctx = global.testcontext("challenge: rejects_connection_for_empty_response");

        ctx.ws.on('message', (m) => {

            ctx.ws.send(JSON.stringify({}))

            ctx.ws.on('close', () => {
                ctx.pass();
            })
        });
    },

    () => {

        let ctx = global.testcontext("challenge: rejects_connection_for_invalid_type");

        ctx.ws.on('message', (m) => {

            ctx.ws.send(JSON.stringify({ type: 'dummy_type' }))

            ctx.ws.on('close', () => {
                ctx.pass();
            })
        });
    }
]