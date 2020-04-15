const _ = require('lodash');
const fs = require('fs');
const spawn = require('child_process').spawn;
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
        const regex = /(\w+)=([^%)]+)/g;
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
                fingerprint['class'] = fingerprint['class'].split('|').map(x => x.trim());
                break;
            case line.startsWith('CPE'):
                fingerprint['cpe'] = line.split(':').slice(1).join(':');
                break;
            default:
                const name = /[^(]+/.exec(line)[0];
                fingerprint[name] = parseFingerprintItem(line);
                break;
        }
    }
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

    // match os without version
    const os = _(results)
        .filter(x => db[x[0]]['class'] !== undefined)
        .filter(x => db[x[0]]['class'][1] !== 'embedded')
        .groupBy(x => db[x[0]]['class'][1])
        .mapValues(xs => xs
            .map(x => x[1])
            .reduce((x, y) => x+y, 0)
        ).value();

    // return Object.entries(os)
    //     .sort((a, b) => b[1] - a[1])
    //     .slice(0, 20);
    return results
        .filter(x => db[x[0]]['class'] !== undefined)
        .filter(x => db[x[0]]['class'][1] !== 'embedded')
        .sort((a, b) => b[1] - a[1])
        .map(x => [db[x[0]]['name'], x[1]]);
};

const getDstPorts = async (dstIp) => {
    const scanner = spawn('nmap', ['-d', '-d', dstIp]);
    const liner = readline.createInterface({
        input: scanner.stdout
    });

    const closeRegex = /Discovered closed port ([0-9]+?)\/tcp/g;
    const openRegex = /Discovered open port ([0-9]+?)\/tcp/g;
    let [open, closed] = [null, null];

    for await (const line of liner) {
        const result = [closeRegex.exec(line), openRegex.exec(line)];

        if (result[0] !== null) closed = result[0][1];
        if (result[1] !== null) open = result[1][1];

        if (closed !== null && open !== null)
            return [open, closed];
    }
};

const tcpScanner = async (probes) => {
    const probeNames = Object.keys(probes);
    const promises = [];
    let srcPort = 60000;

    for (const name of probeNames) {
        const probe = probes[name];
        if (probe.type !== "TCP") continue;

        promises.push(sniffer.sniff(`tcp dst port ${srcPort}`, probe));
        sender.send(srcIp, srcPort, dstIp, probe);
        srcPort += 1;
    }

    return promises;
};

const icmpScanner = async (probes) => {
    const probeNames = Object.keys(probes);
    const promises = [];

    for (const name of probeNames) {
        const probe = probes[name];
        if (probe.type !== "ICMP") continue;

        promises.push(sniffer.sniff(`icmp and src host ${srcIp}`, probe));
        sender.send(srcIp, null, dstIp, probe);
    }

    return promises;
};

const seqScanner = async (probes) => {
    const sleep = (ms) => new Promise(resolve =>
        setTimeout(() => resolve(), ms)
    );

    const promises = [];
    let srcPort = 60100;

    // the probe sending order can not be changed
    for (const name of ['SEQ1', 'SEQ2', 'SEQ3', 'SEQ4', 'SEQ5', 'SEQ6']) {
        promises.push(sniffer.sniff(`tcp dst port ${srcPort}`, probes[name]));
        sender.send(srcIp, srcPort++, dstIp, probes[name]);

        if (name !== 'SEQ6') await sleep(100);
    }

    return promises;
};

const mergeFingerprintItems = (fingerprint) => {
    const result = fingerprint;

    // merge IE
    // let DFI = "O";
    // const dfs = [result['IE1'].DFI, result['IE2'].DFI];
    // if (dfs[0] && dfs[1]) DFI = 'Y';
    // else if (!dfs[0] && !dfs[1]) DFI = 'N';
    // else if (dfs[0] && !dfs[1]) DFI = 'S';

    // let CD = 'O';
    // const cds = [result['IE1'].CD, result['IE2'].CD];
    // if (cds[0] === 'Z' && (cds[1] === 'Z' || cds[1] === 'Z')) CD = 'Z';
    // else if (cds[0] === 'S' && (cds[1] === 'Z' || cds[1] === 'Z')) CD = 'S';

    // let TG = result["IE1"].TG;

    // delete result['IE1'];
    // delete result['IE2'];
    // result['IE'] = {
    //     "R": "Y",
    //     "DFI": DFI,
    //     "CD": CD,
    //     "TG": TG
    // };

    // merge SEQ
    result['WIN'] = {};
    result['OPS'] = {};
    for (const name of Object.keys(result)) {
        if (name === undefined) continue;
        if (!name.startsWith('SEQ') || name === 'SEQ') continue;
        const idx = name[3];

        result['WIN'][`W${idx}`] = result[name]['W'];
        result['OPS'][`O${idx}`] = result[name]['O'];

        delete result[name];
    }

    return result;
};

const main = async () => {
    // const probes = probeSet.setPort(await getDstPorts(dstIp));
    const probes = probeSet.setPort([80, 3000]);
    const probeNames = Object.keys(probes);
    const loadDbPromise = loadDb(dbPath);

    // const promises = [tcpScanner(probes), icmpScanner(probes)].flat();
    const promises_ = [seqScanner(probes)];//.flatMap(async x => await x);
    const promises = await promises_[0];
    let fingerprint = {};

    console.log(promises);
    (await Promise.all(promises)).forEach((elem) =>
        fingerprint[elem.name] = elem
    );

    fingerprint = mergeFingerprintItems(fingerprint);

    await loadDbPromise;
    const os = matchOS(fingerprint);

    console.log(fingerprint);
    console.log(os);
    process.exit(0);
};

main();
