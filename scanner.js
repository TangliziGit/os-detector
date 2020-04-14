const _ = require('lodash');
const fs = require('fs');
const readline = require('readline');
const probeSet = require('./probes.js');
const sender = require('./sender.js');
const sniffer = require('./sniffer.js');

const srcIp = '192.168.0.103';
const dstIp = '39.106.185.26';
const dbPath = 'nmap-os-db';

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

    return results
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(x => [db[x[0]]['name'], x[1]]);
};

const main = async () => {
    const probes = probeSet.setPort([80, 3000]);
    const probeNames = Object.keys(probes);
    let srcPort = 60000;
    let promises = [];
    let fingerprint = {};

    const loadDbPromise = loadDb(dbPath);
    for (const name of probeNames) {
        const probe = probes[name];
        promises.push(sniffer.sniff(`tcp dst port ${srcPort}`, probe));
        sender.send(srcIp, srcPort, dstIp, probe);
        srcPort += 1;
    }

    (await Promise.all(promises))
        .forEach((elem, idx) =>
            fingerprint[probeNames[idx]] = elem
        );

    await loadDbPromise;
    const os = matchOS(fingerprint);

    console.log(os);
    process.exit(0);
};

main();
