const timeout = ms => new Promise(res => setTimeout(res, ms));
window.hpc = null;
window.sodium = {
    onload: async function (sodium) {
        const keys = HotPocket.KeyGenerator.generate(); // Can provide existing hex private key as parameter as well.
        window.hpc = new HotPocket.Client("wss://localhost:8081", keys);

        if (!await window.hpc.connect()) {
            console.log('Connection failed.');
            return;
        }
        console.log('HotPocket Connected.');
        await timeout(2000);
        window.hpc.close();
    }
};