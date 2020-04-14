const pcap = require('pcap');

const WAIT_TIME = 3000;

const listen = (filter) => {
    const session = pcap.createSession('wlp3s0', { filter: filter });

    return new Promise((resolve) => {

        let captured = false;
        session.on('packet', (raw_packet) => {
            const packet = pcap.decode.packet(raw_packet);
            const ip = packet.payload.payload;

            captured = true;
            resolve(ip);
        });

        setTimeout(function () {
            session.close();
            if (!captured)
                resolve(null);
        }, WAIT_TIME);
    });
};

const tcpAnalyser = (ipPacket, probe) => {
    if (ipPacket === null) return {"R":"N"};

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
    else if (BigInt(tcpPacket.seqno) === probe.getAck()) S = 'A';
    else if (BigInt(tcpPacket.seqno) === probe.getAck() + 1n) S = 'A+';

    let A = 'O';
    if (tcpPacket.ackno === 0) A = 'Z';
    else if (BigInt(tcpPacket.ackno) === probe.getSeq()) A = 'S';
    else if (BigInt(tcpPacket.ackno) === probe.getSeq() + 1n) A = 'S+';

    return {
        "R": "Y",
        "DF": (ipPacket.flags.doNotFragment)? "Y": "N",
        "W": tcpPacket.windowSize,
        "S": S,
        "A": A,
        "F": flags,
    };
};

const analyser = {
    "T2": tcpAnalyser,
    "T3": tcpAnalyser,
    "T4": tcpAnalyser,
    "T5": tcpAnalyser,
    "T6": tcpAnalyser,
    "T7": tcpAnalyser,
};

const sniff = async (filter, probe) => {
    const ipPacket = await listen(filter);
    const fingerprint = analyser[probe.name](ipPacket, probe);

    console.log(probe.name, probe.port, fingerprint);
    return fingerprint;
};

module.exports = {
    listen: listen,
    sniff: sniff
};