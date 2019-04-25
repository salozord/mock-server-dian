const express = require('express');
const fs = require('fs');
//const fernet = require('fernet');
const crypto = require('crypto');
var verifier;
var hash;
const Constants = crypto.constants;
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});
const bodyParser = require('body-parser');

const app = express();
const port = process.env.PORT || 8080;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//Punto de acceso raíz (no hace nada realmente)
app.get('/api', function (req, res) {
    console.log('[GET] (ruta: "/api") - Inició petición a la raíz');
    res.status(200).send('Servidor Mock DIAN sirviendo!');
    console.log('[GET] (ruta: "/api") - Éxito(200): ¡Petición a la raíz finalizada éxitosamente!');
});

//Punto de acceso para dar el certificado si es necesario
app.get('/api/publickey', function (req, res) {
    console.log('[GET] (ruta: "/api/publickey") - Inició petición por la llave pública');

    res.status(200).send(publicKey);

    console.log('[GET] (ruta: "/api/publickey") - Éxito(200): ¡Llave pública enviada éxitosamente!');
});

// Punto de acceso para recibir las facturas
app.post('/api/bills', function (req, res, next) {
    console.log('[POST] (ruta: "/api/bills") - Inició recepción de factura');

    let data = req.body;
    if (!data) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se realizó bien la petición. Se envió: ' + data);
        res.status(400).send({ error: true, status: 400, message: "(400) Bad Request - No se realizó bien la petición. No se envió factura alguna." });
        return next();
    }
    if (!data.xml || !data.firma || !data.certificado) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se envió bien la información. Se envió: ' + JSON.stringify(data));
        res.status(400).send({ error: true, status: 400, message: "(400) Bad Request - Se envió información pero incorrectamente." });
        return next();
    }

    try {
        // 1. Obtengo el xml limpio
        let xml = data.xml;

        // 2. Obtengo la llave del cliente
        let llaveCliente = data.certificado;

        // 3. Obtengo la firma, la descifro y comparo
        hash = crypto.createHash('SHA256');
        verifier = crypto.createVerify('SHA256');
        let sign = data.firma;

        hash.update(xml);
        let h = hash.digest('hex');

        verifier.update(h);
        verifier.end();
        let verificacion = verifier.verify({ algorithm: 'rsa', key: llaveCliente, type: publicKey, padding: Constants.RSA_PKCS1_PSS_PADDING, saltLength:Constants.RSA_PSS_SALTLEN_MAX_SIGN }, sign, 'hex');
        console.log(verificacion);

        if (!verificacion) {
            console.log('[POST] (ruta: "/api/bills") - Error(412): Se intentó verificar pero hubo un error de integridad. No coincide la firma.');
            res.status(412).send({ error: true, status: 412, message: "(412) Precondition Failed - Se intentó verificar pero hubo un error de integridad. No coincide la firma." });
            return next();
        }

        res.status(200).send({ error: false, status: 200, message: "¡Factura recibida éxitosamente!" });

        console.log('[POST] (ruta: "/api/bills") - ¡Factura recibida éxitosamente! ¡Se verificó y es completamente integra! :D');
    }
    catch (error) {
        console.log('[POST] (ruta: "/api/bills") - Error(500): Hubo un error dentro del programa. El error fue: ' + error);
        res.status(500).send({ error: true, status: 500, message: `(500) Internal Server Error - Hubo un error dentro del programa. El error fue: ${error.message}` });
        return next();
    }
});

// ESCUCHA
app.listen(port, () => {
    console.log('App listening on port ' + port);
});