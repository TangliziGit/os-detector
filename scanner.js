const _ = require('lodash');
const fs = require('fs');
const readline = require('readline');
const sender = require('./sender.js');
const sniffer = require('./sniffer.js');

let db = [];

const loadDb = async (dbPath) => {
    const parseFingerprintItem = (line) => {
        const regex = /(\w+)=([^%\)]+)/g;
        const item = {};
        let matched;

        while ((matched = regex.exec(line)) != null) {
            let name = matched[1];
            let value = matched[2];

            if (value.includes('|')) {
                value = {"type": "or", "value": value.split('|')};
            } else if (value.includes('-')) {
                const spliced = value.split('-');
                const start = parseInt(spliced[0], 16);
                const end = parseInt(spliced[1], 16);

                value = {"type": "range", "value": [start, end]};
            } else {
                value = {"type": 'value', 'value': value};
            }

            item[name] = value;
        }

        return item;
    };

    const liner = readline.createInterface({
        input: fs.createReadStream(dbPath)
    });

    let fingerprint = {};
    for await (const line of liner) {
        if (line.startsWith('#')) continue;
        if (line === '') {
            db.push(fingerprint);
            continue;
        }

        switch (true) {
            case line.startsWith('Fingerprint'):
                fingerprint = {};
                fingerprint['name'] = line.split(' ').slice(1).join(' ');
                break;
            case line.startsWith('Class'):
                fingerprint['class'] = line.split(' ').slice(1).join(' ');
                break;
            case line.startsWith('CPE'):
                fingerprint['cpe'] = line.split(':').slice(1).join(':');
                break;
            default:
                const name = /[^\(]+/.exec(line)[0];
                fingerprint[name] = parseFingerprintItem(line);
                break;
        }
    };
};

const matchOS = (fingerprint) => {
    let results = [];

    for (let idx = 0; idx < db.length; idx++) {
        const template = db[idx];
        let matchCount = 0;

        for (const key of Object.keys(template)) {
            if (fingerprint[key] === undefined) continue;

            for (const itemKey of Object.keys(template[key])) {
                let value = fingerprint[key][itemKey];
                let templateValue = template[key][itemKey];

                if (value === undefined) continue;
                switch (templateValue.type) {
                    case 'value':
                        if (templateValue.value === value)
                            matchCount++;
                        break;
                    case 'range':
                        if (templateValue.value[0] <= value && value <= templateValue.value[1])
                            matchCount++;
                        break;
                    case 'or':
                        if (templateValue.value.includes(value))
                            matchCount++;
                        break;
                }
            }
        }

        results.push([idx, matchCount]);
    }

    const osList = results
        .sort((a, b) => b[1]-a[1])
        .slice(0, 5)
        .map(x => [db[x[0]]['name'], x[1]]);

    return osList;
};

const main = async () => {
    const probeTypes = ["T2", "T3", "T4", "T5", "T6", "T7"];
    let srcPort = 60000;
    let promises = [];
    let fingerprints = {};

    const loadDbPromise = loadDb('nmap-os-db');
    for (let probeType of probeTypes) {
        promises.push(sniffer.sniff(`tcp dst port ${srcPort}`, probeType));
        sender.send('192.168.0.103', srcPort, '39.106.185.26', 3000, probeType);
        srcPort += 1;
    }

    (await Promise.all(promises)).forEach((elem, idx) => fingerprints[probeTypes[idx]] = elem);

    await loadDbPromise;
    const os = matchOS(fingerprints);
    console.log(os);
    process.exit(0);
};

main();
