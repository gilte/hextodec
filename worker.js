importScripts('./lib/crypto-js.min.js', './lib/elliptic.min.js');

self.onmessage = async (event) => {
    const { rangeStart, rangeEnd, targetHash } = event.data;
    const EC = elliptic.ec;
    const ec = new EC('secp256k1');

    const start = BigInt("0x" + rangeStart);
    const end = BigInt("0x" + rangeEnd);
    const curveN = BigInt("0x" + ec.curve.n.toString(16));

    const step = 115736136738703445724909789689412237499275973113121828343427508099316743301355n; 
    let currentStep = start;

    while (true) { // Loop infinito
        const privateKeyHex = currentStep.toString(16).padStart(64, '0');
        

        const privateKeyBigInt = BigInt("0x" + privateKeyHex);
        if (privateKeyBigInt <= 0n || privateKeyBigInt >= curveN) {
            currentStep += step;
            if (currentStep > end) currentStep = start; // Reinicia ao ultrapassar o intervalo
            continue;
        }
        //loop

        try {
            const keyPair = ec.keyFromPrivate(privateKeyHex);
            const publicKey = keyPair.getPublic(true, 'hex');
            const sha256Hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(publicKey));
            const ripemd160Hash = CryptoJS.RIPEMD160(sha256Hash).toString();
            //console.log(`Generated RIPEMD160: ${ripemd160Hash}`);
            



            if (ripemd160Hash === targetHash) {
                self.postMessage({ type: 'found', privateKey: privateKeyHex });
                break; // Encerra o loop ao encontrar o hash
            }

            if (currentStep % 1000n === 0n) {
                self.postMessage({ type: 'update', message: `Testing key: ${privateKeyHex}` });
            }
        } catch (error) {
            console.error(`Error processing key ${privateKeyHex}:`, error);
        }

        currentStep += step;

        if (currentStep > end) {
            currentStep = start; // Reinicia ao ultrapassar o intervalo
        }
    }
}; 
