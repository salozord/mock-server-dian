const express = require('express');
const fs = require('fs');
const x509 = require('x509.js');
const crypto = require('crypto');
const hash = crypto.createHash('sha256');
const https = require('https');

const app = express();
const port = process.env.PORT || 8080;

var certificado = x509.parseCert(fs.readFileSync('files/mock.cert'));
// var llavePrivada = x509.parseKey(fs.readFileSync('files/mock.key'));

//Punto de acceso raíz (no hace nada realmente)
app.get('/', function(req, res) {
    console.log('[GET] (ruta: "/")');
    res.status(200).send('Servidor Mock DIAN sirviendo!');
});

//Punto de acceso para dar el certificado si es necesario
app.get('/certificate', function (req, res) {
    console.log('[GET] (ruta: "/certificate") - inició petición por el certificado');

    let cert = fs.readFileSync('files/mock.cert').toString('utf-8');
    res.status(200).send(cert);

    console.log('[GET] (ruta: "/certificate") - ¡Certificado enviado éxitosamente! - código: 200');
});

// Punto de acceso para recibir las facturas
app.post('/api', function (req, res) {
    //COSAS PARA FACTURAS Y VERIFICAR !!!
});

https.createServer({
    key: fs.readFileSync('files/mock.key'),
    cert: fs.readFileSync('files/mock.cert')
}, app).listen(port, () => {
    console.log('App listening on port ' + port);
});