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

const tcpAnalyser = (ipPacket) => {
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

    return {
        "R": "Y",
        "DF": (ipPacket.flags.doNotFragment)? "Y": "N",
        "W": tcpPacket.windowSize,
        "S": "None",
        "A": "None",
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
    const fingerprint = analyser[probe.name](ipPacket);

    console.log(probe.name, probe.port, fingerprint);
    return fingerprint;
};

module.exports = {
    listen: listen,
    sniff: sniff
};