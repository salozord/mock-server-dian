const express = require('express');
const fs = require('fs');
const x509 = require('x509.js');
const crypto = require('crypto');
const hash = crypto.createHash('sha256');
const bodyParser = require('body-parser');
// const http = require('http');
// const https = require('https');

const app = express();
const port = process.env.PORT || 8080;


var certificado = x509.parseCert(process.env.CERTIFICATE || fs.readFileSync('files/mock.cert'));
var llavePrivada = x509.parseKey(process.env.PRIVATE_KEY || fs.readFileSync('files/mock.key'));

// No se si esto sea necesario pero lo tengo por si acaso.
// app.use(function (req, res, next) {
//     res.header("Access-Control-Allow-Origin", "*");
//     res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
//     next();
// });
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//Punto de acceso raíz (no hace nada realmente)
app.get('/api', function(req, res) {
    console.log('[GET] (ruta: "/api") - Inició petición a la raíz');
    res.status(200).send('Servidor Mock DIAN sirviendo!');
    console.log('[GET] (ruta: "/api") - Éxito(200): ¡Petición a la raíz finalizada éxitosamente!');
});

//Punto de acceso para dar el certificado si es necesario
app.get('/api/certificate', function (req, res) {
    console.log('[GET] (ruta: "/api/certificate") - Inició petición por el certificado');

    let cert = process.env.CERTIFICATE || fs.readFileSync('files/mock.cert').toString('utf-8');
    res.status(200).send(cert);

    console.log('[GET] (ruta: "/api/certificate") - Éxito(200): ¡Certificado enviado éxitosamente!');
});

// Punto de acceso para recibir las facturas
app.post('/api/bills', function (req, res, next) {
    console.log('[POST] (ruta: "/api/bills") - Inició recepción de factura');
    console.log(req);
    console.log(req.headers);
    let data = req.body;
    if(!data) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se realizó bien la petición. Se envió: ' + data);
        res.status(400).send({error: true, status: 400, message: "(400) Bad Request - No se realizó bien la petición. No se envió factura alguna."});
        return next();
    }
    if(data.xml == undefined || data.firma == undefined || data.certificado == undefined || data.key == undefined) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se envió bien la información. Se envió: ' + data);
        res.status(400).send({error: true, status: 400, message: "(400) Bad Request - Se envió información pero incorrectamente."});
        return next();
    }
    
    // TODO: COSAS PARA FACTURAS Y VERIFICAR !!!

    
    console.log('[POST] (ruta: "/api/bills") - ¡Factura recibida éxitosamente!');
});

// COMO QUE NO FUNCIONA ASÍ, COMO SUPONÍA... :(
// https.createServer({
//     key: process.env.PRIVATE_KEY || fs.readFileSync('files/mock.key'),
//     cert: process.env.CERTIFICATE || fs.readFileSync('files/mock.cert')
// }, app).listen(port, () => {
//     console.log('App listening on port ' + port);
// });

// ESTO SI DEBE SERVIR
app.listen(port, () => {
    console.log('App listening on port ' + port);
});

// FUNCIONES ÚTILES
// -----------------------------------------------------------------------

/**
 * Encripta datos según una llave
 * @param {string} data Los datos a encriptar
 * @param {Buffer} llave La llave a usar para encriptar
 */
function encriptar(data, llavePublica) {
    let buffer = Buffer.from(data);
    let encrypted = crypto.publicEncrypt(llavePublica, buffer);
    return encrypted.toString("base64");
}

/**
 * Desencripta datos según una llave
 * @param {string} data Los datos a desencriptar
 * @param {Buffer} llave La llave a usar para desencriptar
 */
function desencriptar(data, llave) {
    var buffer = Buffer.from(data, "base64");
    var decrypted = crypto.privateDecrypt(llave, buffer);
    return decrypted.toString("utf8");
}