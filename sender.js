const raw = require("raw-socket");

const send = (srcIp, srcPort, dstIp, probe) => {
    let protocol = null;
    if (probe.type === "TCP")
        protocol = raw.Protocol.TCP;
    else if (probe.type === "ICMP")
        protocol = raw.Protocol.ICMP;

    const socket = raw.createSocket({
        protocol: protocol,
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

    let buffer = null;
    if (probe.type === "TCP")
        buffer = probe.getTotalTcpBuffer(srcIp, srcPort, dstIp);
    else if (probe.type === "ICMP")
        buffer = probe.getTotalIcmpBuffer(srcIp, dstIp);

    socket.send(buffer, 0, buffer.length, dstIp, beforeSend, afterSend);
};

// send('192.168.0.103', 3000, '39.106.185.26', 3000, "T5");

 module.exports = {
     send: send
 };
