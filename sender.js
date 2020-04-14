const raw = require("raw-socket");
const ip = require('ip');

const getBuffer = (srcIp, srcPort, dstIp, probe) => {
    // IP
    let ipBuffer = probe.ipBuffer;
    ip.toBuffer(srcIp, ipBuffer, 12);
    ip.toBuffer(dstIp, ipBuffer, 16);
    raw.writeChecksum(ipBuffer, 10, raw.createChecksum(ipBuffer));

    // TCP
    let tcpBuffer = probe.tcpBuffer;
    tcpBuffer.writeUInt8(tcpBuffer.length << 2, 12);
    tcpBuffer.writeUInt16BE(srcPort, 0);
    tcpBuffer.writeUInt16BE(probe.port, 2);
    tcpBuffer.writeUInt16BE(0, 16);

    // pseudoBuffer, to calculate tcp checksum.
    let pseudoBuffer = Buffer.from([
        0x00,0x00,0x00,0x00,    // IP: ip src
        0x00,0x00,0x00,0x00,    // IP: ip dst
        0x00,
        0x06, // IP: protocol (ICMP=1, IGMP=2, TCP=6, UDP=17)
        (tcpBuffer.length >> 8) & 0xff, tcpBuffer.length & 0xff
    ]);
    ip.toBuffer(srcIp, pseudoBuffer, 0);
    ip.toBuffer(dstIp, pseudoBuffer, 4);
    raw.writeChecksum(tcpBuffer, 16, raw.createChecksum(Buffer.concat([pseudoBuffer, tcpBuffer])));

    return Buffer.concat([ipBuffer, tcpBuffer]);
};

const send = (srcIp, srcPort, dstIp, probe) => {
    let socket = raw.createSocket({
        protocol: raw.Protocol.TCP,
        addressFamily: raw.AddressFamily.IPv4
    });

    const beforeSend = () => socket.setOption(
        raw.SocketLevel.IPPROTO_IP,
        raw.SocketOption.IP_HDRINCL,
        Buffer.from([0x00, 0x00, 0x00, 0x01]),
        4
    );

    const afterSend = (error, bytes) => {
        if (error)
            console.log("%s Error occurred\n%s", new Date(), error.toString());
        socket.close();
    };

    const buffer = getBuffer(srcIp, srcPort, dstIp, probe);
    socket.send(buffer, 0, buffer.length, dstIp, beforeSend, afterSend);
};

// send('192.168.0.103', 3000, '39.106.185.26', 3000, "T5");

 module.exports = {
     send: send
 };
