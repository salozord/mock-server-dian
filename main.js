const express = require('express');
const fs = require('fs');
//const fernet = require('fernet');
const crypto = require('crypto');
var verify = crypto.createVerify('SHA256');
var hash = crypto.createHash('SHA256');
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
    if (!data.xml || !data.firma || !data.certificado || !data.key) {
        console.log('[POST] (ruta: "/api/bills") - Error(400): No se envió bien la información. Se envió: ' + data);
        res.status(400).send({ error: true, status: 400, message: "(400) Bad Request - Se envió información pero incorrectamente." });
        return next();
    }

    try {
        // 1. Obtengo la llave de sesión
        // let sesion = data.key;
        // sesion = desencriptarPrivada(sesion, privateKey); // REVISAR PORQUE PUEDE SER POR CRISTIAN POR PADDINGS
        // console.log(sesion);
        // sesion = Buffer.from(sesion, 'ascii').toString('utf8'); // REVISAR A VER SI TOCA EN ASCII ANTES
        // console.log(sesion);

        // 2. Obtengo el xml limpio
        let xml = data.xml;
        //xml = descifrarFernet(xml, sesion.toString('base64'));
        console.log(xml); // Acá ya debería ser el xml legible

        // 3. Obtengo el certificado y saco la llave pública de ahí
        let llaveCliente = data.certificado;

        // 4. Obtengo la firma, la descifro y comparo
        let sign = data.firma;
        hash.update(xml);
        let h = hash.digest('hex'); //REVISAR PORQUE CRISTIAN FIRMA DOBLE
        verify.update(h);
        verify.end();
        let verificacion = verify.verify(llaveCliente, sign);

        if (!verificacion) {
            console.log('[POST] (ruta: "/api/bills") - Error(412): Se intentó verificar pero hubo un error de integridad. No coincide la firma.');
            res.status(412).send({ error: true, status: 412, message: "(412) Precondition Failed - Se intentó verificar pero hubo un error de integridad. No coincide la firma." });
            return next();
        }

        res.status(200).send({ error: false, status: 200, message: "¡Factura recibida éxitosamente!" });

        console.log('[POST] (ruta: "/api/bills") - ¡Factura recibida éxitosamente!');
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

// FUNCIONES ÚTILES
// -----------------------------------------------------------------------

/**
 * Desencripta datos según una llave privada
 * @param {string} data Los datos a desencriptar
 * @param {string} llave La llave a usar para desencriptar
 */
function desencriptarPrivada(data, llave) {
    let buffer = Buffer.from(data, 'base64');
    // let decrypted = crypto.privateDecrypt({ key: llave, padding: Constants.RSA_PKCS1_PADDING }, buffer);
    let decrypted = crypto.privateDecrypt(llave, buffer);
    //return decrypted.toString('ascii');
    return decrypted;
}

/**
 * Desencripta datos según una llave pública
 * @param {string} data Los datos a desencriptar
 * @param {string} llave La llave a usar para desencriptar
 */
function desencriptarPublica(data, llave) {
    let buffer = Buffer.from(data, 'base64');
    let decrypted = crypto.publicDecrypt(llave, buffer);
    return decrypted.toString('utf8');
}

// /**
//  * Descifra datos según una llave (siguiendo algoritmo de Fernet)
//  * @param {string} data Los datos a descifrar (EN BASE64)
//  * @param {string} secreto El secreto (llave) a usar (EN BASE64)
//  */
// function descifrarFernet(data, secreto) {
//     let secret = new fernet.Secret(secreto);
//     let token = new fernet.Token({
//         secret: secret,
//         token: data,
//         ttl: 0
//     });
//     return token.decode().toString('utf8');
// }