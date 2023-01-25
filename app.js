var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt')
const saltRounds = 10
var jwt = require('jsonwebtoken');
const secret = 'fullstack-login'


app.use(cors())

const mysql = require('mysql2');
// create the connection to database

// host: 'ap-southeast.connect.psdb.cloud',
// user: 'c65mh8osjqaght4lskrb',
// password: 'pscale_pw_2WpK0cVxpdEcMB44OG1niP4aotba9YHzOa6scv1o3w5',
// database: 'allonline',
// port: 3306,
// ssl: {
//     rejectUnauthorized: false
// }
const connection = mysql.createConnection('mysql://c65mh8osjqaght4lskrb:pscale_pw_2WpK0cVxpdEcMB44OG1niP4aotba9YHzOa6scv1o3w5@ap-southeast.connect.psdb.cloud/allonline?ssl={"rejectUnauthorized":true}');

app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.execute(
            "INSERT INTO customers (email, password, fname, lname, role) VALUES (?, ?, ?, ?, 'admin')",
            [req.body.email, hash, req.body.fname, req.body.lname],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
                res.json({ status: 'ok' })
            }
        );
    });
})



app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM customers WHERE email = ?',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }

            if (users.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
           
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({ status: 'ok', message: 'login success', token })
                } else {
                    res.json({ status: 'error', message: 'login failed' })
                }
            });
        }
    );
})

app.post('/loginAdmin', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM admin WHERE email = ?',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }

            if (users.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
           
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    var token = jwt.sign({ email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({ status: 'ok', message: 'login success', token })
                } else {
                    res.json({ status: 'error', message: 'login failed' })
                }
            });
        }
    );
})

app.post('/authen', jsonParser, function (req, res, next) {
    try {
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({status: 'ok', decoded})
    } catch (err) {
        res.json({status: 'error', message: err.message})
    }
})

app.listen(3333, jsonParser, function () {
    console.log('CORS-enabled web server listening on port 3333')
})