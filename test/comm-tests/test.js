const global = require('./global')
const challenge_tests = require('./test_challenge')

function runtests() {
    challenge_tests.run();
}

global.init('wss://localhost:8081');
runtests();