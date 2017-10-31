/**
 * Created by pradeepkar on 27/10/17.
 */
var express = require('express');
var router = express.Router();

var Person = require('../.././db/whoopitapp_db.js');
var crypto = require('crypto');

var personModel = Person.getModel();
var getPersonSchema = Person.getPersonSchema();

router.post('/register', function(req,res){
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Methods', 'PUT, GET, POST, DELETE, OPTIONS');
    res.set("Content-Type",'application/text');
    var newPerson = new personModel(req.body);
    var user_salt = crypto.randomBytes(16).toString('hex');
    var cryptPass = crypto.pbkdf2Sync(req.body.password, user_salt, 1000, 64, 'sha1').toString('hex');
    newPerson.salt = user_salt;
    newPerson.hash = cryptPass;
    console.log(newPerson.save());
    newPerson.save(function(err, Person){
        if(err)
            res.status(500).send();
        else
            res.send(Person);
        console.log('Registered!');
    });

});

router.post('/login', function(req,res){
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Methods', 'PUT, GET, POST, DELETE, OPTIONS');
    res.set("Content-Type",'application/text');
    console.log(req.body);

    personModel.findOne({email: req.body.email}, function(err, Person){
        if(err)
            res.status(500).send();
        else
        if(Person == null){
            console.log('not found');
            res.status(404).send();
        }
        else{
            if(Person){
                var pas_salt = Person.salt;
                var pas_hash = crypto.pbkdf2Sync(req.body.password, pas_salt, 1000, 64, 'sha1').toString('hex');

                if(pas_hash == Person.hash){
                    res.send(Person);
                    console.log('Logged In!');
                }
                else{
                    res.status(404).send();
                    console.log('wrong pass');
                }
            }
        }
    })

});
module.exports = router;