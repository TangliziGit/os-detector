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
    const ip = req.body.ip;

    let result;
    try {
        result = await scanner.scan(ip);
        resp.send(result);
    } catch (e) {
        resp.status(404).send("");
    }
});

app.listen(3000);