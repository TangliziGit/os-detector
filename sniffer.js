const pcap = require('pcap');

const listen = (filter) => {
    const session = pcap.createSession('lo', { filter: filter });

    session.on('packet', function (raw_packet) {
        const packet = pcap.decode.packet(raw_packet);
        const tcp = packet.payload.payload.payload;

        console.log(tcp);
    });
};

// listen("tcp dst port 1080");

module.exports = {
    listen: listen
};