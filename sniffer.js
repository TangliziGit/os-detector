const pcap = require('pcap');
const session = pcap.createSession('lo', { filter: "ip proto \\tcp" });
 
const listen = (dst_port) => session.on('packet', function (raw_packet) {
    const packet = pcap.decode.packet(raw_packet);

    const tcp = packet.payload.payload.payload;

    if (tcp.dport === dst_port) {
        console.log(tcp);
    }
});

module.exports = {
    listen: listen
};