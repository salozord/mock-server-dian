const express = require('express');
const fs = require('fs');
const x509 = require('x509.js');
const crypto = require('crypto');
const hash = crypto.createHash('sha256');
const http = require('http');
const https = require('https');

const app = express();
const port = process.env.PORT || 8080;

var certificado = x509.parseCert(fs.readFileSync('files/mock.cert'));
// var llavePrivada = x509.parseKey(fs.readFileSync('files/mock.key'));

// No se si esto sea necesario pero lo tengo por si acaso.
// app.use(function (req, res, next) {
//     res.header("Access-Control-Allow-Origin", "*");
//     res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
//     next();
// });

//Punto de acceso raíz (no hace nada realmente)
app.get('/api', function(req, res) {
    console.log('[GET] (ruta: "/") - Inició petición a la raíz');
    res.status(200).send('Servidor Mock DIAN sirviendo!');
    console.log('[GET] (ruta: "/") - Éxito(200): ¡Petición a la raíz finalizada éxitosamente!');
});

//Punto de acceso para dar el certificado si es necesario
app.get('/certificate', function (req, res) {
    console.log('[GET] (ruta: "/certificate") - Inició petición por el certificado');

    let cert = fs.readFileSync('files/mock.cert').toString('utf-8');
    res.status(200).send(cert);

    console.log('[GET] (ruta: "/certificate") - Éxito(200): ¡Certificado enviado éxitosamente!');
});

// Punto de acceso para recibir las facturas
app.post('/api/facturas', function (req, res) {
    console.log('[POST] (ruta: "/api") - Inició recepción de factura');
    let data = req.body;
    if(!data) {
        console.log('[POST] (ruta: "/api") - Error(400): No se realizó bien la petición. Se envió: ' + data);
        res.status(400).send({error: true, status: 400, message: "(400) Bad Request - No se realizó bien la petición. No se envió factura alguna."});
    }
    if(data.xml == undefined || data.firma == undefined || data.certificado == undefined) {
        console.log('[POST] (ruta: "/api") - Error(400): No se envió bien la información. Se envió: ' + data);
        res.status(400).send({error: true, status: 400, message: "(400) Bad Request - Se envió información pero incorrectamente."});
    }
    
    //COSAS PARA FACTURAS Y VERIFICAR !!!
    
    
    console.log('[POST] (ruta: "/api") - ¡Factura recibida éxitosamente!');
});

https.createServer({
    key: fs.readFileSync('files/mock.key'),
    cert: fs.readFileSync('files/mock.cert')
}, app).listen(port, () => {
    console.log('App listening on port ' + port);
});