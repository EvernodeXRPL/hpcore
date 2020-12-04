window.sodium = {
    onload: async function () {
        const keys = HotPocket.KeyGenerator.generate(); // Can provide existing hex private key as parameter as well.
        const hpc = new HotPocket.Client("wss://localhost:8081", keys);

        if (!await hpc.connect()) {
            console.log('Connection failed.');
            return;
        }
        console.log('HotPocket Connected.');

        // This will get fired if HP server disconnects unexpectedly.
        hpc.on(HotPocket.events.disconnect, () => {
            console.log('Server disconnected');
        })

        // This will get fired when contract sends an output.
        hpc.on(HotPocket.events.contractOutput, (bytes) => {
            const msg = new TextDecoder().decode(bytes);
            console.log("Contract output>> " + msg);
        })

        // This will get fired when contract sends a read response.
        hpc.on(HotPocket.events.contractReadResponse, (bytes) => {
            const msg = new TextDecoder().decode(bytes);
            console.log("Contract read response>> " + msg);
        })

        hpc.sendContractReadRequest("Hello");
        hpc.sendContractInput("World!")

        // When we need to close HP connection:
        // hpc.close();
    }
};