const config = require("./config.json");

const express = require("express");
const fetch = require("node-fetch");
const { Client } = require('@elastic/elasticsearch');
const fs = require("fs");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();

const log = (string) => {
    console.log(`${new Date().toISOString()}: ${string}`);
};

async function connectToEs() {
    log(`[LOG] Try to connect to es`);
    const esClient = new Client({
        node: config.ELASTICSEARCH_NODE,
        auth: {
            username: config.ELASTICSEARCH_USER,
            password: config.ELASTICSEARCH_PASSWORD
        },
        tls: {
            ca: fs.readFileSync(config.ELASTICSEARCH_CA_FILE),
            rejectUnauthorized: false
        }
    });
    try {
        const pingResponse = await esClient.ping();
        if (pingResponse === true) {
            log("[LOG] Elasticsearch client is up");
        } else {
            log("[ERROR] Elasticsearch client ping returned false");
        }
    } catch (err) {
        log(`[ERROR] Elasticsearch cluster is down: ${err.message}`);
        log("[ERROR] Exit process");
        process.exit(1);
    }
    return esClient;
}

async function main() {
    log(`[LOG] Config file: ${JSON.stringify(config)}`);
    const esClient = await connectToEs();

    app.use(bodyParser.json({limit: "50mb"}));

    app.post(config.PATH_SENSOR_EPOCH_RESULT, async (req, res) => {
        log(`[LOG] Received ${Object.entries(req.body.encrypted_bloom_filters).length} epoch bloom filters for: ${req.body.sensor_id}`);
        const epochStartTimestamp = req.body.epoch_start_timestamp * 1000;
        const epochEndTimestamp = req.body.epoch_end_timestamp * 1000;
        const sensorId = req.body.sensor_id;
        const bloomFilters = req.body.encrypted_bloom_filters;
        // store the bloomfilter of each epoch for each consumer
        for (let [pkc, bloomFilter] of Object.entries(bloomFilters)) {
            // check if index for pkc exists
            const pkcIndexExists = await esClient.indices.exists({
                index: pkc
            });
            // create index if neccessary
            if (pkcIndexExists === false) {
                await esClient.indices.create({
                    index: pkc,
                });
                await esClient.indices.putMapping({
                    index: pkc,
                    properties: {
                        epochStartTimestamp: { type: "long" },
                        epochEndTimestamp: { type: "long" },
                        sensorId: { type: "int" },
                        bloomFilter: { type: "text", index: "not_analyzed" }
                    }
                })
            }
            // store epoch bloom filter
            await esClient.index({
                index: pkc,
                body: {
                    epochStartTimestamp,
                    epochEndTimestamp,
                    sensorId,
                    bloomFilter,
                },
            });
        }
        res.sendStatus(200);
    });

    app.post(config.PATH_AVAILABLE_EPOCHS, async (req, res) => {
        log(`[LOG] Received request for available epochs: ${JSON.stringify(req.body)}`);
        // check if request contains the pkc field
        if (!("pkc" in req.body)) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Public key of consumer (pkc) not found",
                },
            });
            return;
        }
        // check if index for pkc exists
        const pkcIndexExists = await esClient.indices.exists({
            index: req.body.pkc,
        });
        // if index does not exist return empty response
        if (pkcIndexExists === false) {
            res.send({
                result: [],
            });
            return;
        }
        // search entries for the corresponding consumer public key
        const searchResult = await esClient.search({
            index: req.body.pkc,
            size: config.ELASTICSEARCH_SIZE_LIMIT,
        });
        log(`[LOG] ES search result: ${JSON.stringify(searchResult.hits.hits)}`);
        // build result with available epochs
        const esResults = searchResult.hits.hits;
        const result = [];
        for (let i = 0; i < esResults.length; i += 1) {
            result.push({
                epochId: esResults[i]._id,
                epochStartTimestamp: esResults[i]._source.epochStartTimestamp,
                epochEndTimestamp: esResults[i]._source.epochEndTimestamp,
                sensorId: esResults[i]._source.sensorId,
            });
        }
        res.status(200);
        res.send({
            result,
        });
    });

    app.post(config.PATH_CLIENT_QUERY, async (req, res) => {
        log(`Received query request for ${JSON.stringify(req.body.pkc)}`);
        // check if request contains the pkc field
        if (!"pkc" in req.body || !"serializedPkc" in req.body || !"serializedGaloisKeys" in req.body
            || !"serializedRelinKeys" in req.body) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Public key (pkc or serializedPkc or serializedGaloisKeys or erializedRelinKeys) of consumer not found",
                },
            });
            return;
        }

        // check if the index for pkc exists
        const pkcIndexExists = await esClient.indices.exists({
            index: req.body.pkc,
        });
        // return error response if index was not found
        if (pkcIndexExists === false) {
            res.status(400);
            res.send({
                "error": {
                    "message": `Public key of consumer (pkc) <${req.body.pkc}> not found in database`,
                },
            });
            return;
        }
        // return error response if epoch ids array is empty
        const epochIdsToSearch = req.body.epochs_ids;
        if (epochIdsToSearch.length === 0) {
            res.status(404);
            res.send({
                "error": {
                    "message": `Epoch ids array is empty: <${epochIdsToSearch}>`,
                },
            });
            return;
        }
        // search in ES the epochs with requested ids
        const searchResult = await esClient.search({
            index: req.body.pkc,
            query: {
                terms: {
                    _id: epochIdsToSearch,
                },
            },
        });
        log(`[LOG] ES search result: ${searchResult.hits.hits.length} hits`);
        // if epochs were not found for every requested id return error response
        if (searchResult.hits.hits.length !== epochIdsToSearch.length) {
            res.send({
                "error": {
                    "message": "Not all epochs were found. Check again requested epochs' ids",
                },
            });
            return;
        }

        // build result bloom filter
        let bloomFiltersCipherText = [];
        for (let i = 0; i < searchResult.hits.hits.length; i += 1) {
            bloomFiltersCipherText.push(searchResult.hits.hits[i]._source.bloomFilter);
        }

        console.log(Object.keys(req.body))
         const response = await fetch(config.MULTIPLY_SERVICE_URL, {
            method: "POST",
            body: JSON.stringify({
                publicKey: req.body.serializedPkc,
                serializedGaloisKeys: req.body.serializedGaloisKeys,
                serializedRelinKeys: req.body.serializedRelinKeys,
                encryptedBloomFilters: bloomFiltersCipherText,
            }),
            headers: { 'Content-Type': 'application/json' },
        });
        const data = await response.json();

        const resultBloomFilterCipherText = data.result;

        // compute queried epochs for aditional info
        let queriedEpochs = [];
        for (let i = 0; i < searchResult.hits.hits.length; i += 1) {
            const epoch = searchResult.hits.hits[i];
            queriedEpochs.push({
                epochId: epoch._id,
                epochStartTimestamp: epoch._source.epochStartTimestamp,
                epochEndTimestamp: epoch._source.epochEndTimestamp,
                sensorId: epoch._source.sensorId,
            });
        }
        res.status(200);
        res.send({
            result: {
                totalEpochsCount: searchResult.hits.hits.length,
                queriedEpochs,
                bloomFilter: resultBloomFilterCipherText,
            },
        });
        log(`[LOG] Result computed successfully`);
    });

    app.post(config.PATH_DELETE_PKC_DATA, async (req, res) => {
        log(`[LOG] Received delete request: ${JSON.stringify(req.body)}`);
        // check if request contains the pkc field
        if (!("pkc" in req.body)) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Public key (pkc) of consumer not found",
                }
            });
            return;
        }
        const pkcIndexExists = await esClient.indices.exists({
            index: req.body.pkc,
        });
        // return if index does not exists
        if (pkcIndexExists === true) {
            // delete index for pkc
            await esClient.indices.delete({
                index: req.body.pkc,
            });;
        }
        // delete pkc - serialized pkc pair
        await esClient.deleteByQuery({
            index: config.PUBLIC_KEYS_INDEX,
            body: {
                query: {
                    match: {
                        pkc: req.body.pkc,
                    },
                },
            },
        });
        res.send({
            result: {
                message: "Pair deleted successfully.",
            }
        })
    });

    app.post(config.PATH_REGISTER_PKC, async (req, res) => {
        log(`[LOG] Received register request: ${JSON.stringify(req.body)}`);
        // check if request contains the pkc field
        if (!"pkc" in req.body || !"serializedPkc" in req.body || !"serializedGaloisKeys" in req.body) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Public key (pkc or serializedPkc or serializedGaloisKeys) of consumer not found",
                }
            });
            return;
        }
        // check if request contains the sensor_id field
        if (!("sensor_id" in req.body)) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Sensor id (sensor_id) of sniffer not found",
                }
            });
            return;
        }
        try {
            const pkcIndexExists = await esClient.indices.exists({
                index: req.body.pkc,
            });
            // create index for pkc if it does not exist
            if (pkcIndexExists === false) {
                await esClient.indices.create({
                    index: req.body.pkc,
                });
            }

            // add pair pkc - serialized pkc in es index
            const pkcPairsIndexExists = await esClient.indices.exists({
                index: config.PUBLIC_KEYS_INDEX,
            });
            // create index for pkc - serialized pkc pairs if it does not exist
            if (pkcPairsIndexExists === false) {
                await esClient.indices.create({
                    index: config.PUBLIC_KEYS_INDEX,
                });
            }
            // add pair at index
            await esClient.index({
                index: config.PUBLIC_KEYS_INDEX,
                body: {
                    pkc: req.body.pkc,
                    serializedPkc: req.body.serializedPkc,
                    serializedGaloisKeys: req.body.serializedGaloisKeys,
                },
            });

            // register pkc to sensor
            const sensorId = req.body.sensor_id;
            // check if sensor exists in server's configuration
            if (!(sensorId in config.SNIFFERS_DATA)) {
                res.status(404);
                res.send({
                    "error": {
                        "message": `Sensor <${sensorId}> is not available`,
                    }
                });
                return;
            }
            // register pkc to sniffer
            const snifferRegisterUrl = config.SNIFFERS_DATA[sensorId].SNIFFER_URL_REGISTER_PKC;
            const response = await fetch(snifferRegisterUrl, {
                method: "POST",
                body: JSON.stringify({
                    pkc: req.body.pkc,
                    serializedPkc: req.body.serializedPkc,
                    serializedGaloisKeys: req.body.serializedGaloisKeys,
                }),
                headers: {'Content-Type': 'application/json'},
            });
            const data = await response.json();
            // send registration response to client
            if ("result" in data) {
                res.status(200);
                res.send({
                    "result": {
                        "message": `Public key (pkc) ${req.body.pkc} registered to ${sensorId}`,
                    }
                })
            } else {
                res.status(500);
                res.send({
                    "error": {
                        "message": `Public key (pkc) ${req.body.pkc} could NOT be registered to ${sensorId}`,
                    }
                })
            }
        } catch (error) {
            log(`[ERROR] ${error}`);
            res.send({
                "error": {
                    "message": `Public key (pkc) ${req.body.pkc} could NOT be registered to ${req.body.sensor_id}`,
                }
            });
        }
    });

    app.post(config.PATH_UNREGISTER_PKC, async (req, res) => {
        log(`[LOG] Received unregister request: ${JSON.stringify(req.body)}`);
        // check if request contains the pkc field
        if (!"pkc" in req.body || !"serializedPkc" in req.body) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Public key (pkc) of consumer not found",
                }
            });
            return;
        }
        // check if request contains the sensor_id field
        if (!("sensor_id" in req.body)) {
            res.status(400);
            res.send({
                "error": {
                    "message": "Sensor id (sensor_id) of sniffer not found",
                }
            });
            return;
        }
        try {
            // check if sensor exists in server's configuration
            const sensorId = req.body.sensor_id;
            if (!(sensorId in config.SNIFFERS_DATA)) {
                res.status(404);
                res.send({
                    "error": {
                        "message": `Sensor <${sensorId}> is not available`,
                    },
                });
                return;
            }
            // unregister pkc from sniffer
            const snifferUnregisterUrl = config.SNIFFERS_DATA[sensorId].SNIFFER_URL_UNREGISTER_PKC;
            const response = await fetch(snifferUnregisterUrl, {
                method: "POST",
                body: JSON.stringify({
                    pkc: req.body.pkc,
                    serializedPkc: req.body.serializedPkc,
                }),
                headers: {'Content-Type': 'application/json'},
            });
            const data = await response.json();
            // send registration response to client
            if ("result" in data) {
                res.status(200);
                res.send({
                    "result": {
                        "message": `Public key (pkc) ${req.body.pkc} unregistered from ${sensorId}`,
                    }
                });
            } else {
                res.status(500);
                res.send({
                    "error": {
                        "message": `Public key (pkc) ${req.body.pkc} could NOT be unregistered from ${req.body.sensor_id}`,
                    }
                })
            }
        } catch (error) {
            log(`[ERROR] ${error}`);
            res.send({
                "error": {
                    "message": `Public key (pkc) ${req.body.pkc} could NOT be unregistered to ${req.body.sensor_id}`,
                }
            });
        }
        
    });

    app.get(config.PATH_AVAILABLE_SENSORS, (req, res) => {
        const result = [];
        const sensors = Object.keys(config.SNIFFERS_DATA);
        for (const sensor of sensors) {
            result.push({
                sensor,
                location: config.SNIFFERS_DATA[sensor].LOCATION,
            });
        }
        res.send({ result });
    });

    app.get(config.PATH_CLIENT_INTERFACE, (req, res) => {
        res.sendFile("", {
            root: path.join(__dirname, "client"),
        });
    });

    app.get("/", (req, res) => {
        res.sendFile("index.html", {
            root: path.join(__dirname, "client"),
        });
    });

    app.get("/login", (req, res) => {
        res.redirect("http://localhost:4200/")
    });

    app.get("/client/imports.js", (req, res) => {
        res.sendFile("imports.js", {
            root: path.join(__dirname, "client"),
        });
    });

    app.listen(config.SERVER_PORT, () => {
        log(`[LOG] Server listening on port ${config.SERVER_PORT}`);
    });
}

main();
