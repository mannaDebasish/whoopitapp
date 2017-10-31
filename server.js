var express = require('express');
var app = express();

var bodyParser = require('body-parser');
var path = require('path');
var crypto = require('crypto');


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static(__dirname + '/view'));


/*================ linking all controller js file ========================*/
user = require('./controller/user/user.js');



/*================ connect to the controller js file with respect to the url  ========================*/
app.use('/user', user);



app.listen(8080, function () {
    console.log( "Server Running Successfully on 8080" );
});

