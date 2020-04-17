const IcmpProbe = require('./probes').IcmpProbe;
const pcap = require('pcap');

const WAIT_TIME = 4000;

const listen = (filter, probe) => {
    const session = pcap.createSession('eth0', { filter: filter });

    return new Promise((resolve) => {

        let captured = false;
        session.on('packet', (raw_packet) => {
            const packet = pcap.decode.packet(raw_packet);
            const ip = packet.payload.payload;

            if (!(probe instanceof IcmpProbe) || probe.getIpLength() === ip.length) {
                captured = true;
                session.close();
                resolve([ip, raw_packet.buf]);
            }
        });

        setTimeout(function () {
            session.close();
            if (!captured)
                resolve([null, null]);
        }, WAIT_TIME);
    });
};

const tcpOption = (rawBuffer) => {
    const position = ((rawBuffer[14] & 0x0f) << 2) + 34;
    const optionBuffer = rawBuffer.slice(position);
    let pos = 0;
    let result = "";

    while (optionBuffer[pos] !== 0) {
        if (optionBuffer[pos] === 0) { pos++; result += 'L'; continue;}
        if (optionBuffer[pos] === 1) { pos++; result += 'N'; continue;}

        const kind = optionBuffer[pos];
        const length = optionBuffer[pos+1];

        if (kind === 2) {
            const content = ((optionBuffer[pos+2] << 8) + optionBuffer[pos+3]).toString(16).toUpperCase();
            result += `M${content}`;
        } else if (kind === 3) {
            const content = optionBuffer[pos+2].toString(16).toUpperCase();
            result += `W${content}`;
        } else if (kind === 4) {
            result += 'S';
        } else if (kind === 8) {
            const TSval = (BigInt(optionBuffer[pos+2]) << 24n) + (BigInt(optionBuffer[pos+3]) << 16n) +
                (BigInt(optionBuffer[pos+4]) << 8n) + BigInt(optionBuffer[pos+5]);
            const TSecr = (BigInt(optionBuffer[pos+6]) << 24n) + (BigInt(optionBuffer[pos+7]) << 16n) +
                (BigInt(optionBuffer[pos+8]) << 8n) + BigInt(optionBuffer[pos+9]);

            const T1 = (TSval === 0n)? '0': '1';
            const T2 = (TSecr === 0n)? '0': '1';
            result += `T${T1}${T2}`;
        }

        pos += length;
    }

    return result;
};

const tcpAnalyser = (ipPacket, rawBuffer, probe) => {
    if (ipPacket === null) return {"name": probe.name, "R":"N"};

    const tcpPacket = ipPacket.payload;

    let flags = "";
    if (tcpPacket.flags.ece) flags += "E";
    if (tcpPacket.flags.urg) flags += "U";
    if (tcpPacket.flags.ack) flags += "A";
    if (tcpPacket.flags.psh) flags += "P";
    if (tcpPacket.flags.rst) flags += "R";
    if (tcpPacket.flags.syn) flags += "S";
    if (tcpPacket.flags.fin) flags += "F";

    let S = 'O';
    if (tcpPacket.seqno === 0) S = 'Z';
    else if (BigInt(tcpPacket.seqno) === probe.getTcpAck()) S = 'A';
    else if (BigInt(tcpPacket.seqno) === probe.getTcpAck() + 1n) S = 'A+';

    let A = 'O';
    if (tcpPacket.ackno === 0) A = 'Z';
    else if (BigInt(tcpPacket.ackno) === probe.getTcpSeq()) A = 'S';
    else if (BigInt(tcpPacket.ackno) === probe.getTcpSeq() + 1n) A = 'S+';

    let TG = ipPacket.ttl, bitnum = 0;
    while (TG !== 1) {bitnum+=1; TG >>= 1;}
    if ((TG = 1 << bitnum ) < ipPacket.ttl)
        TG <<= 1;

    return {
        "name": probe.name,
        "R": "Y",
        "DF": (ipPacket.flags.doNotFragment)? "Y": "N",
        "W": tcpPacket.windowSize.toString(16),
        "S": S,
        "A": A,
        "F": flags,
        "TG": TG.toString(16)
    };
};

const icmpAnalyser = (ipPacket, rawBuffer, probe) => {
    if (ipPacket === null) return {"name": probe.name, "R": "N"};

    const icmpPacket = ipPacket.payload;

    let CD = 'O';
    if (icmpPacket.code === 0) CD = 'Z';
    else if (icmpPacket.code === probe.getIcmpCode()) CD = 'S';

    let TG = ipPacket.ttl, bitnum = 0;
    while (TG !== 1) {bitnum+=1; TG >>= 1;}
    if ((TG = 1 << bitnum ) < ipPacket.ttl)
        TG <<= 1;

    return {
        "name": probe.name,
        "R": "Y",
        "DFI": false, // ipPacket.flags.doNotFragment,
        "CD": CD,
        "TG": TG.toString(16)
    }
};

const ecnAnalyser = (ipPacket, rawBuffer, probe) => {
    if (ipPacket === null) return {"name": probe.name, "S": "N"};

    const tcpPacket = ipPacket.payload;

    let TG = ipPacket.ttl, bitnum = 0;
    while (TG !== 1) {bitnum+=1; TG >>= 1;}
    if ((TG = 1 << bitnum ) < ipPacket.ttl)
        TG <<= 1;

    let CC = 'O';
    let [ece, cwr] = [tcpPacket.flags.ece, tcpPacket.flags.cwr];
    if (ece && cwr) CC = 'S';
    else if (ece && !cwr) CC = 'Y';
    else if (!ece && !cwr) CC = 'N';

    return {
        "name": probe.name,
        "R": "Y",
        "DF": (ipPacket.flags.doNotFragment)? "Y": "N",
        "W": tcpPacket.windowSize.toString(16),
        "TG": TG.toString(16),
        "O": tcpOption(rawBuffer),
        "CC": CC,
    };
};

const seqAnalyser = (ipPacket, rawBuffer, probe) => {
    if (ipPacket === null) return {"name": probe.name, "R": "N"};

    const tcpPacket = ipPacket.payload;

    if (probe.name === 'SEQ1')
        return {
            "name": probe.name,
            "W": tcpPacket.windowSize.toString(16),
            "O": tcpOption(rawBuffer),
            "T1": tcpAnalyser(ipPacket, rawBuffer, probe)
        };

    return {
        "name": probe.name,
        "W": tcpPacket.windowSize.toString(16),
        "O": tcpOption(rawBuffer),
    }
};

const udpAnalyser = (ipPacket, rawBuffer, probe) => {
    if (ipPacket === null) return {"name": probe.name, "R": "N"};

    let TG = ipPacket.ttl, bitnum = 0;
    while (TG !== 1) {bitnum+=1; TG >>= 1;}
    if ((TG = 1 << bitnum ) < ipPacket.ttl)
        TG <<= 1;

    return {
        "R": "Y",
        "DF": (ipPacket.flags.doNotFragment)? "Y": "N",
        "TG": TG.toString(16),
    }
};

const analyser = {
    "T2": tcpAnalyser,
    "T3": tcpAnalyser,
    "T4": tcpAnalyser,
    "T5": tcpAnalyser,
    "T6": tcpAnalyser,
    "T7": tcpAnalyser,
    "IE1": icmpAnalyser,
    "IE2": icmpAnalyser,
    "ECN": ecnAnalyser,
    "SEQ1": seqAnalyser,
    "SEQ2": seqAnalyser,
    "SEQ3": seqAnalyser,
    "SEQ4": seqAnalyser,
    "SEQ5": seqAnalyser,
    "SEQ6": seqAnalyser,
    "U1": udpAnalyser
};

const sniff = async (filter, probe) => {
    const [ipPacket, rawBuffer] = await listen(filter, probe);
    const result = analyser[probe.name](ipPacket, rawBuffer, probe);

    console.log(result);
    return result;
};

module.exports = {
    listen: listen,
    sniff: sniff
};
