window.sodium = {
    onload: async function () {
        const keys = HotPocket.KeyGenerator.generate(); // Can provide existing hex private key as parameter as well.
        const hpc = new HotPocket.Client("dummy", keys,
            [
                "wss://localhost:8081",
                "wss://localhost:8082",
                "wss://localhost:8083"],
            [
                "ed7e538ac55cf6347a0bd6f83f77426fb0c0406549f766286eb85dc4835423feda",
                "ede1e0710d3e500b96616a1f0e8c96379d9a638d92c04a1a64a842aca511fb6760",
                "ed9c39ce5c1e861b54cc5060cee80d4a487add19636a16cc328526ec9783ee721f"
            ], 2);

        if (!await hpc.connect()) {
            console.log('Connection failed.');
            return;
        }
        console.log('HotPocket Connected.');

        // This will get fired if HP server disconnects unexpectedly.
        hpc.on(HotPocket.events.disconnect, () => {
            console.log('Disconnected');
        })

        // This will get fired as servers connects/disconnects after the initial connection establishment.
        hpc.on(HotPocket.events.connectionChange, (server, action) => {
            console.log(server + " " + action);
        })

        // This will get fired when contract sends an output.
        hpc.on(HotPocket.events.contractOutput, (output) => {
            console.log("Contract output>> " + output);
        })

        // This will get fired when contract sends a read response.
        hpc.on(HotPocket.events.contractReadResponse, (response) => {
            console.log("Contract read response>> " + response);
        })

        hpc.sendContractReadRequest("Hello");
        hpc.sendContractInput("World!")

        // When we need to close HP connection:
        // hpc.close();
    }
};