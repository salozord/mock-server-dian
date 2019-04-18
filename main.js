const express = require('express');
const fs = require('fs');
var https = require('https');

const app = express();
const port = process.env.PORT || 8080;

//Punto de acceso raíz
app.get('/', function(req, res) {
    console.log('[GET] (ruta: "")');
    res.send('Servidor Mock DIAN sirviendo!');
});

//Punto de acceso para dar el certificado
app.get('/certificate', function (req, res) {
    console.log('GET - inició petición por el certificado');
    
});

https.createServer({
    key: fs.readFileSync('files/mock.key'),
    cert: fs.readFileSync('files/mock.cert')
}, app).listen(port, () => {
    console.log('App listening on port ' + port);
});