const raw = require("raw-socket");
const ip = require('ip');

// ############################## IP ##############################
// IP: only checksum, src ip, dst ip can be changed.
// let ipBuffer = Buffer.from([
//     0x45,                   // IP: Version (0x45 is IPv4)
//     0x00,                   // IP: Differentiated Services Field
//     0x00,0x3c,              // IP: Total Length
//     0x00,0x01,              // IP: Identification
//     0x40,                   // IP: Flags (0x20 Don't Fragment)
//     0x00,                   // IP: Fragment Offset
//     0x40,                   // IP: TTL (0x40 is 64)
//     0x06,                   // IP: protocol (ICMP=1, IGMP=2, TCP=6, UDP=17, static value)
//     0x00,0x00,              // IP: checksum for IP part of this packet
//     0x00,0x00,0x00,0x00,    // IP: ip src
//     0x00,0x00,0x00,0x00,    // IP: ip dst
// ]);

const ipBuffers = [
    Buffer.from([0x45, 0x00, 0x00, 0x3c, 0x59, 0x5a, 0x40, 0x00, 0x30, 0x06, 0xf3, 0x5f, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01]),
];

// ############################## TCP #############################
// TCP: only src port, dst port, header length, checksum will be changed.
// let tcpBuffer = new Buffer([
//     0x00,0x00,              // TCP: src port (should be random)
//     0x00,0x00,              // TCP: dst port (should be the port you want to scan)
//     0x00,0x00,0x00,0x00,    // TCP: sequence number (should be random)
//     0x00,0x00,0x00,0x00,    // TCP: acquitment number (must be null because WE are intiating the SYN, static value)
//     0x00,0x02,              // TCP: header length (data offset) && flags (fin=1,syn=2,rst=4,psh=8,ack=16,urg=32, static value)
//     0x72,0x10,              // TCP: window
//     0x00,0x00,              // TCP: checksum for TCP part of this packet)
//     0x00,0x00,              // TCP: ptr urgent
//     0x02,0x04,              // TCP: options
//     0x05,0xb4,              // TCP: padding (mss=1460, static value)
//     0x04,0x02,              // TCP: SACK Permitted (4) Option
//     0x08,0x0a,              // TCP: TSval, Length
//         0x01,0x75,0xdd,0xe8,// value
//         0x00,0x00,0x00,0x00,// TSecr
//     0x01,                   // TCP: NOP
//     0x03,0x03,0x07          // TCP: Window scale
// ]);
const tcpBuffers = [
    Buffer.from([0xd6, 0xc1, 0x04, 0x38, 0x0c, 0x8b, 0x3f, 0x0c, 0xd4, 0x9b, 0x37, 0xb0, 0xa0, 0x00, 0x00, 0x80, 0x12, 0x54, 0x00, 0x00,
        0x03, 0x03, 0x0a, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0a, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02]),
];

const getBuffer = (number, src_ip, src_port, dst_ip, dst_port) => {
    // IP
    let ipBuffer = ipBuffers[number];
    ip.toBuffer(src_ip, ipBuffer, 12);
    ip.toBuffer(dst_ip, ipBuffer, 16);
    raw.writeChecksum(ipBuffer, 10, raw.createChecksum(ipBuffer));

    // TCP
    let tcpBuffer = tcpBuffers[number];
    tcpBuffer.writeUInt8(tcpBuffer.length << 2, 12);
    tcpBuffer.writeUInt16BE(src_port, 0);
    tcpBuffer.writeUInt16BE(dst_port, 2);

    // pseudoBuffer, to calculate tcp checksum.
    let pseudoBuffer = new Buffer([
        0x00,0x00,0x00,0x00,    // IP: ip src
        0x00,0x00,0x00,0x00,    // IP: ip dst
        0x00,
        0x06, // IP: protocol (ICMP=1, IGMP=2, TCP=6, UDP=17)
        (tcpBuffer.length >> 8) & 0xff, tcpBuffer.length & 0xff
    ]);
    ip.toBuffer(src_ip, pseudoBuffer, 0);
    ip.toBuffer(dst_ip, pseudoBuffer, 4);
    raw.writeChecksum(tcpBuffer, 16, raw.createChecksum(Buffer.concat([pseudoBuffer, tcpBuffer])));

    return Buffer.concat([ipBuffer, tcpBuffer]);
};

const send = (src_ip, src_port, dst_ip, dst_port) => {
    let socket = raw.createSocket({
        protocol: raw.Protocol.TCP,
        addressFamily: raw.AddressFamily.IPv4
    });

    const beforeSend = () => socket.setOption(
        raw.SocketLevel.IPPROTO_IP,
        raw.SocketOption.IP_HDRINCL,
        new Buffer ([0x00, 0x00, 0x00, 0x01]),
        4
    );

    const afterSend = (error, bytes) => {
        if (error)
            console.log("%s Error occurred\n%s", new Date(), error.toString());
        else
            console.log("%s Sent %s bytes for %s:%s", new Date(), bytes, dst_ip, dst_port);
    };

    const buffer = getBuffer(0, src_ip, src_port, dst_ip, dst_port);
    socket.send(buffer, 0, buffer.length, dst_ip, beforeSend, afterSend);
};

 send('127.0.0.1', 3000, '127.0.0.1', 1080);

 module.exports = {
     send: send
 };
