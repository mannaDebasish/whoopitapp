/*var MongoClient = require('mongodb').MongoClient;
var mongoose = require('mongoose');

function mongo_connect( dbname, callback )
{
  MongoClient.connect('mongodb://whoopitapp:whoopitapp@ds243285.mlab.com:43285/' + dbname, callback );
}

function mongoose_connect( dbname, callback )
{
  var conn = mongoose.createConnection('mongodb://whoopitapp:whoopitapp@ds243285.mlab.com:43285/' + dbname);
  callback( null, conn );
  return conn;
}*/





/*
module.exports.mongoose = mongoose;
module.exports.mongoose_connect = mongoose_connect;
module.exports.mongo_test_connect = function ( callback ) { return mongo_connect( 'whoopitapp', callback ); };
module.exports.mongoose_test_connect = function ( callback ) { return mongoose_connect( 'whoopitapp', callback ); };


var db = mongoose.connection;

db.once('open', function() {
    console.log('MongoDB Successfully Connected!!');
});
*/


var mongoose = require('mongoose');

mongoose.Promise = global.Promise;

mongoose.connect('mongodb://whoopitapp:whoopitapp@ds243285.mlab.com:43285/whoopitapp');

var db = mongoose.connection;

db.once('open', function() {
    console.log('MongoDB Successfully Connected!!');
});


/*================== User schema ==============*/

var personSchema = mongoose.Schema({
    uname: {
        type: String,
        required: true
    },
    mobile: {type:String, required:true},
    email: {
        type: String,
        unique: true,
        required: true
    },
    f_user:String,
    hash: String,
    salt: String
});
var Person = mongoose.model("Users", personSchema);


module.exports = {
    getModel: function(){
        return Person;
    },
    getPersonSchema: function(){
        return personSchema;
    }
};