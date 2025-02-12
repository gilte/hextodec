importScripts('./lib/crypto-js.min.js', './lib/elliptic.min.js');
self.onmessage = async (event) => {
    const { rangeStart, rangeEnd, targetHash, step } = event.data; // Agora 'step' vem do código principal
    const EC = elliptic.ec;
    const ec = new EC('secp256k1');

    const start = BigInt("0x" + rangeStart);
    const end = BigInt("0x" + rangeEnd);
    const curveN = BigInt("0x" + ec.curve.n.toString(16));

    const stepValue = BigInt(step); // Passando o valor de 'step' para a variável stepValue
    let currentStep = start;

    while (true) {
        const privateKeyHex = currentStep.toString(16).padStart(64, '0');
        
        const privateKeyBigInt = BigInt("0x" + privateKeyHex);
        if (privateKeyBigInt <= 0n || privateKeyBigInt >= curveN) {
            currentStep += stepValue;
            if (currentStep > end) currentStep = start; // Reinicia ao ultrapassar o intervalo
            continue;
        }

        try {
            const keyPair = ec.keyFromPrivate(privateKeyHex);
            const publicKey = keyPair.getPublic(true, 'hex');
            const sha256Hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(publicKey));
            const ripemd160Hash = CryptoJS.RIPEMD160(sha256Hash).toString();

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

        currentStep += stepValue;

        if (currentStep > end) {
            currentStep = start; // Reinicia ao ultrapassar o intervalo
        }
    }
};
