const config = require("./config.json");

const express = require("express");
const SEAL = require("node-seal");
const bodyParser = require("body-parser");

const log = (string) => {
    console.log(`${new Date().toISOString()}: ${string}`);
};

async function initSeal() {
    const seal = await SEAL();
    const schemeType = seal.SchemeType.bfv;
    const securityLevel = seal.SecurityLevel.tc128;

    const parms = seal.EncryptionParameters(schemeType);

    // Set the PolyModulusDegree
    parms.setPolyModulusDegree(config.POLY_MODULUS_DEGREE);

    // Create a suitable set of CoeffModulus primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(config.POLY_MODULUS_DEGREE, Int32Array.from(config.BIT_SIZES))
    );

    // Set the PlainModulus to a prime of bitSize 20.
    parms.setPlainModulus(
        seal.PlainModulus.Batching(config.POLY_MODULUS_DEGREE, config.BIT_SIZE)
    );

    const context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        securityLevel // Enforce a security level
    );

    if (!context.parametersSet()) {
        throw new Error(
            'Could not set the parameters in the given context. Please try different encryption parameters.'
        )
    }
    return { seal, context };
}

function encrypt(publicKey, bloomFilter, seal, context) {
    // define encoder and key generator
    const encoder = seal.BatchEncoder(context);
    const keyGenerator = seal.KeyGenerator(context);

    // define and load public key
    const publicKeyObj = keyGenerator.createPublicKey();
    publicKeyObj.load(context, publicKey);

    // define encryptor used to obtain the cipher text
    const encryptor = seal.Encryptor(context, publicKeyObj);

    // obtain plain text from array
    const plainText = encoder.encode(Int32Array.from(bloomFilter));

    // encrypt the plaintext and obtain ciphertext
    const cipherText = encryptor.encrypt(plainText);
    return cipherText.save();
}

function multiply(serializedRelinKeys, serializedGaloisKeys, encryptedBloomFilters, seal, context) {
    // define evaluator 
    const evaluator = seal.Evaluator(context);

    // define and load result cipher text
    const resultCipherText = seal.CipherText();
    resultCipherText.load(context, encryptedBloomFilters[0]);

    // multiply under encryption
    for (let i = 1; i < encryptedBloomFilters.length; i += 1) {
        const bfCipherText = seal.CipherText();
        bfCipherText.load(context, encryptedBloomFilters[i]);
        evaluator.multiply(bfCipherText, resultCipherText, resultCipherText); // Op (A), Op (B), Op (Dest)
    }

    // create key generator to load keys
    const keyGenerator = seal.KeyGenerator(context);

    // reliniarize under encryption
    const relinKeys = keyGenerator.createRelinKeys();
    relinKeys.load(context, serializedRelinKeys);
    evaluator.relinearize(resultCipherText, relinKeys, resultCipherText);

    // sum elements under encryption
    const galoisKeys = keyGenerator.createGaloisKeys();
    galoisKeys.load(context, serializedGaloisKeys);
    evaluator.sumElements(resultCipherText, galoisKeys, seal.SchemeType.bfv, resultCipherText);

    return resultCipherText.save();
}

const app = express();

async function main() {
    const { seal, context } = await initSeal();

    app.use(bodyParser.json({limit: "50mb"}));

    app.get("/", (req, res) => {
        res.send({});
    });

    app.post(config.MULTIPLY_PATH, (req, res) => {
        log("[LOG] Received multiply request");
        // handle wrong request
        if (!"publicKey" in req.body || !"encryptedBloomFilters" in req.body || !"serializedGaloisKeys" in req.body
            || !"serializedRelinKeys" in req.body) {
            res.status(400);
            res.send({
                error: {
                    message: "Wrong request. Public key or encrypted bloom filters missing",
                }
            });
            log("[ERROR] Wrong request. Public key or bloom filter missing");
            return;
        }
        try {
            const startDate = new Date();
            const resultCipherText = multiply(req.body.serializedRelinKeys, req.body.serializedGaloisKeys, req.body.encryptedBloomFilters, seal, context);
            const endDate = new Date();
            log(`[LOG] Multiplication lasted: ${(endDate.getTime() - startDate.getTime()) / 1000} seconds`);
            res.send({
                result: resultCipherText,
            });
        } catch (error) {
            log(`[ERROR] ${error}`);
            console.log(error.stack)
            res.status(404);
            res.send({
                error: {
                    message: error.message,
                }
            });
        }
    });

    app.post(config.ENCRYPTION_PATH, (req, res) => {
        log("[LOG] Received encryption request");
        // handle wrong request
        if (!"publicKey" in req.body || !"bloomFilter" in req.body) {
            res.status(400);
            res.send({
                error: {
                    message: "Wrong request. Public key or bloom filter missing",
                }
            });
            log("[ERROR] Wrong request. Public key or bloom filter missing");
            return;
        }
        // encrypt requested data and send it back
        try {
            const startDate = new Date();
            const encryptedBloomFilter = encrypt(req.body.publicKey, req.body.bloomFilter, seal, context);
            const endDate = new Date();
            log(`[LOG] Encryption lasted: ${(endDate.getTime() - startDate.getTime()) / 1000} seconds`);
            res.send({
                result: encryptedBloomFilter,
            });
        } catch (error) {
            log(error.stack)
            res.status(404);
            res.send({
                error: {
                    message: error.message,
                }
            })
            log("[ERROR] Encryption failed");
        }
    });

    app.post(config.ENCRYPTION_PATH_BATCH, (req, res) => {
        log("[LOG] Received batch encryption request");
        // handle wrong request
        if (!"publicKey" in req.body || !"bloomFilter" in req.body) {
            res.status(400);
            res.send({
                error: {
                    message: "Wrong request. Public key or bloom filter missing",
                }
            });
            log("[ERROR] Wrong request. Public key or bloom filter missing");
            return;
        }
        // encrypt requested data and send it back
        try {
            const startDate = new Date();
            let result = [];
            for (let i = 0; i < req.body.publicKey.length; i += 1) {
                const encryptedBloomFilter = encrypt(req.body.publicKey[i], req.body.bloomFilter[i], seal, context);
                result.push(encryptedBloomFilter);
            }
            const endDate = new Date();
            log(`[LOG] Batch encryption for ${result.length} elements lasted: ${(endDate.getTime() - startDate.getTime()) / 1000} seconds`);
            res.send({
                result,
            });
        } catch (error) {
            log(error.stack)
            res.status(404);
            res.send({
                error: {
                    message: error.message,
                }
            });
            log("[ERROR] Encryption failed");
        }
    });

    app.listen(config.PORT, () => {
        log(`[LOG] Server is listening on port ${config.PORT}`);
    });
}

main();
