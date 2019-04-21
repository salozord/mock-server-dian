const express = require('express');
const fs = require('fs');
const fernet = require('fernet');
//const x509 = require('x509.js');
const { Certificate, PrivateKey } = require('@fidm/x509');
const crypto = require('crypto');
const verify = crypto.createVerify('SHA256');
const hash = crypto.createHash('SHA256');
const bodyParser = require('body-parser');

const app = express();
const port = process.env.PORT || 8080;

var certificado = Certificate.fromPEM(process.env.CERTIFICATE || fs.readFileSync('files/mock.cert'));
var llavePrivada = PrivateKey.fromPEM(process.env.PRIVATE_KEY || fs.readFileSync('files/mock.key'));

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

    let cert = process.env.CERTIFICATE || certificado.toString('utf-8');
    res.status(200).send(cert);

    console.log('[GET] (ruta: "/api/certificate") - Éxito(200): ¡Certificado enviado éxitosamente!');
});

// Punto de acceso para recibir las facturas
app.post('/api/bills', function (req, res, next) {
    console.log('[POST] (ruta: "/api/bills") - Inició recepción de factura');

    let data = req.body;
    if(!data) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se realizó bien la petición. Se envió: ' + data);
        res.status(400).send({error: true, status: 400, message: "(400) Bad Request - No se realizó bien la petición. No se envió factura alguna."});
        return next();
    }
    if(!data.xml || !data.firma|| !data.certificado || !data.key) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se envió bien la información. Se envió: ' + data);
        res.status(400).send({error: true, status: 400, message: "(400) Bad Request - Se envió información pero incorrectamente."});
        return next();
    }
    
    // TODO: COSAS PARA FACTURAS Y VERIFICAR !!!
    // CRISTIAN ME MANDA LA LLAVE DE SESION CIFRADA CON MI PUBLICA
    // EL XML CIFRADO CON LA LLAVE DE SESION
    // EL CERTIFICADO CONTIENE SU PUBLICA Y
    // LA FIRMA ESTA CON SHA256 Y ME MANDA EL HASH DEL XML CIFRADO CON SU LLAVE PRIVADA

    // RSA, SHA256, FERNET

    // 1. Obtengo la llave de sesión y la dejo en base64
    let sesion = data.key;
    //sesion = Buffer.from(sesion, 'hex').toString('base64');
    sesion = desencriptarPrivada(sesion, llavePrivada.toPEM()); // REVISAR PORQUE PUEDE SER POR CRISTIAN POR PADDINGS
    sesion = Buffer.from(sesion, 'utf8').toString('base64');

    // 2. Obtengo el xml limpio
    let xml = data.xml;
    xml = Buffer.from(xml, 'hex').toString('base64');
    xml = descifrarFernet(xml, sesion);
    console.log(xml); // Acá ya debería ser el xml legible

    // 3. Obtengo el certificado y saco la llave pública de ahí
    let info = Buffer.from(data.certificado, 'hex').toString('utf8');
    let cert = Certificate.fromPEM(Buffer.from(info)); // REVISAR QUE SE LE MANDE EN FORMATO PEM

    // 4. Obtengo la firma, la descifro y comparo
    let sign = data.firma; 
    hash.update(xml);
    let h = hash.digest('hex'); //REVISAR PORQUE CRISTIAN FIRMA DOBLE
    verify.update(h);
    verify.end();
    let verificacion = verify.verify(cert.publicKey.toPEM(), sign);

    if(!verificacion) {
        console.log('[POST] (ruta: "/api/bills") - Error(412): Se intentó verificar pero hubo un error de integridad. No coincide la firma.');
        res.status(412).send({error: true, status: 412, message: "(412) Precondition Failed - Se intentó verificar pero hubo un error de integridad. No coincide la firma."});
        return next();
    }

    res.status(200).send({error: false, status: 200, message: "¡Factura recibida éxitosamente!"});
    
    console.log('[POST] (ruta: "/api/bills") - ¡Factura recibida éxitosamente!');
});

// ESCUCHA
app.listen(port, () => {
    console.log('App listening on port ' + port);
});

// FUNCIONES ÚTILES
// -----------------------------------------------------------------------

/**
 * Desencripta datos según una llave privada
 * @param {string} data Los datos a desencriptar
 * @param {Buffer} llave La llave a usar para desencriptar
 */
function desencriptarPrivada(data, llave) {
    let buffer = Buffer.from(data, 'base64');
    let decrypted = crypto.privateDecrypt(llave, buffer);
    return decrypted.toString('utf8');
}

/**
 * Desencripta datos según una llave pública
 * @param {string} data Los datos a desencriptar
 * @param {Buffer} llave La llave a usar para desencriptar
 */
function desencriptarPublica(data, llave) {
    let buffer = Buffer.from(data, 'base64');
    let decrypted = crypto.publicDecrypt(llave, buffer);
    return decrypted.toString('utf8');
}

/**
 * Descifra datos según una llave (siguiendo algoritmo de Fernet)
 * @param {string} data Los datos a descifrar (EN BASE64)
 * @param {string} secreto El secreto (llave) a usar (EN BASE64)
 */
function descifrarFernet(data, secreto) {
    let secret = new fernet.Secret(secreto);
    let token = new fernet.Token({
        secret: secret,
        token: data,
        ttl: 0
    });
    return token.decode().toString('utf8');
}