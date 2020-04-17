const dns = require('dns');
const util = require('util');
const path = require('path');
const bodyParser = require('body-parser');
const express = require('express');
const scanner = require('./scanner/scanner');

const app = express();
const root = '/';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({'extended': true}));

app.get(root, (req, resp) => {
    resp.sendFile(path.join(__dirname, 'index.html'));
});

app.post(root, async (req, resp) => {
    const address = req.body.ip;

    let result;
    try {
        const addr = await util.promisify(dns.lookup)(address);
        if (addr.family !== 4) throw new Error();

        console.log(addr, address);
        result = await scanner.scan(addr.address);
        resp.send(result);
    } catch (e) {
        console.log(e);
        resp.status(404).send("");
    }
});

app.listen(3000);
