window.sodium = {
    onload: async function (sodium) {
        const keys = HotPocket.KeyGenerator.generate(); // Can provide existing hex private key as parameter as well.
        window.hpc = new HotPocket.Client("wss://localhost:8081", keys);

        if (!await window.hpc.connect()) {
            console.log('Connection failed.');
            return;
        }
        console.log('HotPocket Connected.');

        // This will get fired when contract sends a read response.
        hpc.on(HotPocket.events.contractReadResponse, (bytes) => {
            const response = new TextDecoder().decode(bytes);
            console.log("Contract read response>> " + response);
        })

        hpc.sendContractReadRequest("Hello");

        //window.hpc.close();
    }
};