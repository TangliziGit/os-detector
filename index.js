const dns = require('dns');
const util = require('util');
const path = require('path');
const bodyParser = require('body-parser');
const express = require('express');
const scanner = require('./scanner/scanner');

const app = express();
const root = '/';
let using = false;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({'extended': true}));

app.get(root, (req, resp) => {
    resp.sendFile(path.join(__dirname, 'index.html'));
});

app.post(root, async (req, resp) => {
    let response = {ok: true, content: null};
    if (using) {
        response.ok = false;
        response.content = "error, too many scanning task.";
        resp.status(404).send(response);
        return;
    }

    const address = req.body.ip;
    let result;

    try {
        using = true;
        const addr = await util.promisify(dns.lookup)(address);
        if (addr.family !== 4) throw new Error();

        console.log(addr, address);
        result = await scanner.scan(addr.address);
        using = false;
        response.content = result;
        resp.send(response);
    } catch (e) {
        console.log(e);
        using = false;
        response.ok = false;
        response.content = "input error, please check the net address and scan again.";
        resp.status(404).send(response);
    }
});

app.listen(3000);
