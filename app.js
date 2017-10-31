var _ = require('underscore');
require('colors');
var async = require('async');

function startup_server ( config, cb )
{
    var _               =     require('underscore');
    var mongoose        =     require('mongoose');
    //Express plus other dependencies

    var express         =     require('express');
    var Resource        =     require('express-resource');
    var session         =     require('express-session');
    var cookieParser    =     require('cookie-parser');
    var bodyParser      =     require('body-parser');
    var engines         =     require('consolidate'); //Needed for template language
    var MongoStore      =     require('connect-mongo')({session: session});
    var passport        =     require('passport');
    var flash           =     require('connect-flash');
    var https           =     require('https');
    var moment          =     require("moment");


    /* initialize express app */
    var app             = express();
    var DB              = require(__dirname + '/db/whoopitapp');
    var ansi            = require('ansi');
    var cursor          = ansi(process.stdout);
    var fs              = require('fs');
    app.ta_config = config;


    function log( msg )
    {
        if ( config.logger )
            config.logger.ws( msg );
        else
            console.log( msg );
    }

    function blue( msg )
    {
        var blue_msg =  msg.bold.blue;
        log( blue_msg );
    }

    console.log( "Connecting to DB: " + config.dbname );
    app.db = DB.mongoose_connect( config.dbname, cb || function () { } );

    _.each([ 'activity', 'assignment', 'audit', 'clients', 'content_comment',
        'feedback', 'file', 'organization', 'task', 'User', 'conversation', 'conversation_bucket', 'program'
    ], function (x) { require(__dirname + '/server/schema/' + x )(app, mongoose); } );

    // Load and start the reminder through agenda
    var ta_agenda = require('./server/api/ta_agenda').start(app);
    require(__dirname + '/server/api/reminders')(app,mongoose);
    var api_assignment  =     require(__dirname + '/server/api/assignments-api')( app );
    var api_conversation  =     require(__dirname + '/server/api/conversations-api')( app );
    /**
     * Set static directories
     * When these came after the app.resource calls, they weren't working correctly. Not sure why.
     */
    //compress causes mark_complete to throw Error: Can't set headers after they are sent.
    //app.use(express.compress());
    /* usefull for tracing Error: Can't set headers after they are sent.
     var writeHead = res.writeHead;
     res.writeHead = function( code, headers ){
     console.trace("Headers written here");
     res.writeHead = writeHead;
     res.writeHead(code, headers);
     };
     */

    app.disable('x-powered-by');
    // app.use('/', express.static(__dirname + '/public/'));
    app.use('/oldpublic/' , express.static(__dirname + '/public/'));
    app.use('/assets'     , express.static(__dirname + '/appnew/tpl/pornography-landing/assets/'));
    app.use('/'           , express.static(__dirname + '/appnew/'));
    app.use('/public'     , express.static(__dirname + '/appnew/public/'));
    app.use('/app/'       , express.static(__dirname + '/app/'));
    app.use('/newapp/'    , express.static(__dirname + '/appnew/'));
    app.use('/files/'     , express.static(config.uploads_dir));

    app.ta_config.session_secret = 'e39d8722e5cca60e9011021736ca96b7ac2433bd';
    app.ta_config.session_store  = new MongoStore({ db:'sessions',url:'mongodb://localhost:27017/' + config.dbname}, function () {});
    app.use(cookieParser(app.ta_config.session_secret));

    app.use(bodyParser.urlencoded({
        extended: true
    }));
    app.use(bodyParser.json());

    app.use(session({
        // the callback to MongoStore avoids Error: Error setting TTL index on collection
        // https://github.com/kcbanner/connect-mongo/pull/58#issuecomment-32148111
        store: app.ta_config.session_store,
        secret: app.ta_config.session_secret,
        resave: true,
        saveUninitialized: true
    }));
    app.use(passport.initialize());
    app.use(passport.session());

    // setting up for CORS access as I test the mobile app
    app.use(function(req, res, next){
        res.header("Access-Control-Allow-Origin", "http://localhost:8100");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        res.header('Access-Control-Allow-Methods', 'PUT, GET, POST, DELETE, OPTIONS');
        res.header("Access-Control-Allow-Credentials", true);
        res.header("Access-Control-Expose-Headers", "Origin, X-Requested-With, Content-Type, Accept, set-cookie");

        if(req.method == 'OPTIONS')
            res.send(200);
        else
            next();
    });

    try { fs.mkdirSync( config.upload_dir ); } catch (e) {}
    // Audit request/response logging
    app.use(require(__dirname + '/server/logging')( config.logger || console.log ));


    app.use(flash());

    //passport
    passport.serializeUser(function(user, done) {
        //console.log("Serialing user id" + user._id);
        //console.log("Serialing user id " + user );
        done(null, user._id);
    });

    passport.deserializeUser(function(id, done) {
        app.db.models.User.findById(id, function(err, user) {
            //if (user){ console.log("Deserializing " + user.username ); }
            //else { console.log("Deserializing didn't find " + id ); }
            done(null, user);
        });
    });

    function autologin( req, res, next )
    {
        function promote( user, authstuff, c ) {
            var organization = authstuff.org;
            if ( config.paramlogin && req.query.BADtherapist )
            {
                blue("AUTO Promoting to therapist IN QUERY PARAM: " + req.query.BADtherapist );
                if ( user ) user.roles.therapist = true;
            }
            if ( config.paramlogin && req.query.BADadmin )
            {
                blue("AUTO Promoting to admin IN QUERY PARAM: " + req.query.BADadmin );
                if ( user ) user.roles.admin = true;
            }
            user.save( function ( err, saved_user ) {
                async.series([
                    function ( c ){
                        if ( config.paramlogin && req.query.BADadmin )
                            organization.add_admin( saved_user._id, c );
                        else
                            c();
                    },
                    function ( c ){
                        if ( config.paramlogin && req.query.BADtherapist )
                            organization.add_therapist( saved_user._id, c );
                        else
                            c();
                    },
                ], c );
            });
            req.session.BAD = true;
        }

        function find_org( user_auth_info, c ) {
            var BYU = "Brigham Young University Counseling and Career Center";
            function findOrCreateOrg( org_name, c )
            {
                app.db.models.Organization.findOrCreate( { name: org_name }, { name: org_name }, c );
            }
            if ( req.query.BADorg ) {
                findOrCreateOrg( req.query.BADorg, c );
            }
            else if ( user_auth_info.email ){
                app.db.models.User.find( { email: user_auth_info.email }, function ( err, user ) {
                    if ( user ) {
                        app.db.models.Organization.findById( user.org, function ( err, org ) {
                            if ( org ) {
                                c( null, org || BYU );
                            }
                            else {
                                findOrCreateOrg( BYU, c );
                            }
                        });
                    }
                    else {
                        findOrCreateOrg( BYU, c );
                    }
                });
            }
            else {
                findOrCreateOrg( BYU, c );
            }
        }

        function auth_with_org ( user_auth_info ) {
            find_org( user_auth_info, function ( err, org ) {
                user_auth_id = user_auth_info.netid || user_auth_info.email;
                blue("AUTOLOGGING IN: " + user_auth_id + " to org " + org.name + ": " + org._id );
                user_auth_info.org = org;
                passport.authenticate('ta_devel', { authstuff: user_auth_info, promote: promote })(req, res, next);
            });
        }

        if ( config.autologin )
            auth_with_org( { netid: config.autologin } );
        else if ( config.paramlogin && req.query.BADemail )
            auth_with_org( { email: req.query.BADemail } );
        else if ( config.paramlogin && req.query.BAD )
            auth_with_org( { netid: req.query.BAD } );
        else
        {
            //console.log("AUTOLIGGING TURNED OFF:")
            next();
        }
    }


    /*************************************************************************************************/
    /*************************************************************************************************/
    /*************************************************************************************************/
    //first app.get or app.post must occur after all the app.use's
    /*************************************************************************************************/
    /*************************************************************************************************/
    /*************************************************************************************************/
    /*************************************************************************************************/
    app.use(autologin); // for DEVEL and DEBUG ONLY

    // allow ene-to-end test to reset database and hardcodes
    if ( config.test ) {
        app.get("/reset_database", function (req, res) {
            function droptest() {
                app.db.db.dropDatabase( function ( err, ok ) {
                    if ( err ) console.log( "dropdatabase ", err );
                    require(__dirname + '/server/hardcodes')( app, function ( err, ok) {
                        if ( err ) console.log( "hardcodes ", err );
                        res.send(200);
                    });
                });
            }

            //console.log ("Resetting DB");
            if ( app.db.readyState == 1 )
            {
                droptest();
            }
            else {
                app.db.db.on('open',  function ( err, db ) {
                    droptest();
                });
            }

        });
    }
    else
    {
        require(__dirname + '/server/hardcodes')( app );
    }




    /* find user's user model for users that authenticate through byu CAS system*/
    var byu_cas = new BYUCASStraegy( config.local_server_url + '/auth/byu-cas', config.local_server_url, function ( netid, success, failure ) {
        app.db.models.User.findOrCreateByNetId( netid, function ( err, user ) {
            if ( err ) {
                console.log( "Error: BYUCASStraegy " + err );
                return failure();
            }
            console.log( "Success: BYUCASStraegy " + netid + " " + user );
            return success( user );
        });
    });
    passport.use( byu_cas );
    /* find user's user model for users that authenticate through BAD= */
    passport.use( new TADevelStrategy( function ( authstuff, success, failure ) {
        //console.log("Trying to load " + JSON.stringify(authstuff, null, 4) );
        var attributes;
        if ( authstuff.netid ) {
            attributes =  {
                username: authstuff.netid+ '@byu_unknown.therapyally.com',
                email: authstuff.netid+ '@byu_unknown.therapyally.com',
                organization: authstuff.org._id,
            };
        }
        else
        {
            attributes =  {
                username: authstuff.email,
                email: authstuff.email,
                organization: authstuff.org._id,
            };
        }
        if ( authstuff.org.authInfo && authstuff.org.authInfo.auth_type && authstuff.org.authInfo.auth_type == "byu-cas" ) {
            attributes.authid = { netid: authstuff.netid, auth_type: authstuff.org.authInfo.auth_type };
        }

        app.db.models.User.findOrCreateUser(authstuff.netid,
            authstuff.org,
            attributes,
            {}, /* no upsert */
            function ( err, user ) {
                if ( err ){
                    console.log( "Error: TADevelStrategy ", err );
                    return failure();
                }
                return success( user );
            });
    }));
    /* find user's user model that authenticate through login_as */
    passport.use( new TASignInAsStrategy() );
    /* find user's user model that authenticate through therapy ally's password authentication */
    var ta_normal_strategy = new TANormalStrategy( function ( email, password, success, failure ) {
        app.db.models.User.findByEmail( email, function ( err, user ) {
            if ( err || !user ) {
                var msg = "Unrecognized user email " + email;
                if ( err )
                    console.log( "Error: TANormalStrategy " + err );
                else
                    console.log( "TANormalStrategy: " + msg );
                return failure( { error: msg });
            }
            user.verityPassword( password, function ( err , valid ) {
                if ( err || ! valid ) {
                    console.log( "TANormalStrategy Unrecognized user password: " + err + " " + valid );
                    console.log( "TANormalStrategy error: " + err + " " + valid );
                    return failure( { error: "Unrecognized user password" });
                }
                if ( valid ) {
                    return success( user );
                    console.log( "TANormalStrategy Success " + user._id );
                }
            });
        });
    });

    passport.use( ta_normal_strategy );

    app.all('/rest*', function (req, res, next) {
        if ( req.isAuthenticated() ) { next(); }
        else res.json(401, { error: "Not authenticated", auth_url: "/auth" });
    });
    app.all('/api*', function (req, res, next) {
        if ( req.isAuthenticated() ) next();
        else res.status(401).json({ error: "Not authenticated", auth_url: "/auth" });
    });
    app.all('/api/therapist/*', function (req, res, next) {
        req.user.isTherapist( function () { next(); },
            function () { res.send(401, "User" + req.user.prettyLogging() + " is not a therapist"); } );
    });
    app.all('/api/admin/*', function (req, res, next) {
        req.user.isMultiTenantAdmin( function () { next(); },
            function () { res.send(401, "User" + req.user.prettyLogging() + " is not a multi-tenant administrator"); } );
    });

    app.get("/stripe/coupon/:coupon", function(req, res){
        stripe.coupons.retrieve(req.params.coupon,
            function(err, coupon) {
                res.send(coupon);
            }
        );
    });

    var api_program       =    require( __dirname + '/server/program' )( app );
    var pornography_program = require( __dirname + '/server/pornography_program' )( app );
    var emotional_intelligence_program = require( __dirname + '/server/emotional_intelligence_program' )( app );
    var vivint_program = require( __dirname + '/server/vivint_program' )( app );

    app.post("/stripe/:plan", function (req, res) {
        // get variables from body
        var email = req.body.email;
        var name = req.body.name;
        var password = req.body.password;
        var plan = req.params.plan;
        var token = req.body.token;
        var coupon = req.body.coupon;
        var cust = {
            source: token,
            email: email,
            plan: plan,
            description: name
        };
        if( coupon && coupon != "" )
            cust.coupon = coupon;
        var customer = stripe.customers.create(cust, function(err, customer) {
            // error
            if( err ) {
                console.log( "Error getting stripe customer info from stripe token. Error: ", err );
                return res.redirect('/');
            }
            // if no error
            else {
                console.log("Creating a new user");
                app.db.models.User.findByEmail( email, function ( err, user ) {
                    // if there's no user with that email already
                    if ( err || !user ) {
                        var msg = "Unrecognized user email Adding user " + email;
                        app.db.models.Organization.findOne( { name: "Kyle Auto Assign" }, function ( err, org ) {
                            if ( err ) {
                                console.log( "Kyle Auto Assign org not found" );
                                return res.redirect('/');
                            }

                            // create a new client
                            var client = new app.db.models.User( {
                                email: email,
                                name: name,
                                organization: org,
                                lastMarkedComplete: new Date(),
                                plan: plan,
                                pornographyDailyTracker: moment(),
                                tags: ['pornography']
                            });

                            api_program.assignUserProgram( user, pornography_program.pornography_oid );

                            // save the new client
                            client.save( function( err, client ) {
                                if ( err ) {
                                    console.log( "Failed to save " + client );
                                    return res.redirect('/');
                                }
                                console.log("Created client", client);
                                client.encryptPassword(password);
                                app.db.models.User.findOne( { name: "Kyle Tew." }, function ( err, kyleuser ) {
                                    if ( err ) {
                                        console.log( "Kyle Tew. therapist not found" );
                                        return res.redirect('/');
                                    }
                                    var api_users = require(__dirname + '/server/api/users')( app );

                                    // add the user to the therapist (in this case, Kyle)
                                    api_users.add_client_to_therapist_id_by_id( kyleuser._id, client._id, function ( err, ojb ) { if ( err ) { console.log( "Error addind " + client + " to therapist " + kyleuser._id ); } } );
                                    app.ta_functions.sendemail_changeally( client.name,
                                        client.email,
                                        "Welcome to Change Ally",
                                        "Welcome to Change Ally! Click on one of the links below to download the app and get started.<br><br> \
                                        <a href=\"https://itunes.apple.com/us/app/changeally/id972408796?mt=8&ign-mpt=uo%3D4\">Apple App Store</a> <br>\
                                        <a href=\"https://play.google.com/store/apps/details?id=com.ionicframework.therapyallytest407145 \">Google App Store</a>" );

                                    // send us a notification email on client signup
                                    app.ta_functions.sendemail_changeally( "Change Ally Signup",
                                        "support@changeally.com",
                                        "Someone signed up",
                                        "Wahoo! Someone just signed up.<br><br>\
                                        name: " + client.name + "<br>\
                                   email: " + client.email + "<br>\
                                   plan: " + plan + "<br>\
                                   coupon: " + coupon + "<br>");

                                    // assign initial activity
                                    var activity = {
                                        "content": "54cfb6ebdf1ff3385fc40fc2", // pornography welcome assignment
                                        "client_id": client._id,
                                        "provider_id": kyleuser._id,
                                        "dueCompleted": moment().add(3, 'days')
                                    };
                                    api_assignment.create_activity(req.app.db, activity);

                                    // // assign initial activities
                                    // var activity = {
                                    //   "content": "54f1705d49a944d50ca8813e", // Thought Control Questionaire
                                    //   "client_id": client._id,
                                    //   "provider_id": kyleuser._id,
                                    //   "dueCompleted": moment().add(3, 'days')
                                    // };
                                    // api_assignment.create_activity(req.app.db, activity);

                                    // var activity = {
                                    //   "content": "54f69e46b3c1ef40677e8821", // Thought-Action Fusion Scale
                                    //   "client_id": client._id,
                                    //   "provider_id": kyleuser._id,
                                    //   "dueCompleted": moment().add(3, 'days')
                                    // };
                                    // api_assignment.create_activity(req.app.db, activity);

                                    // send initial message
                                    var message = {
                                        "text": "Welcome to Change Ally! I'm Kyle and I'll be your coach. Feel free to message anytime. Let me know if you have any questions.",
                                        "message": {
                                            "text": "Welcome to Change Ally! I'm Kyle and I'll be your coach. Feel free to message anytime. Let me know if you have any questions."
                                        }
                                    };

                                    api_conversation.send_message(client.id, kyleuser, message);

                                    // log user in, then redirect to thank you page
                                    passport.authenticate('ta_signin_as', { user_to_become: client })(req, res, function () {
                                        res.redirect('/thankyou');
                                    });
                                });
                            });
                        });
                    }
                    else{
                        // there's already a user with that email
                        // send myself a notification about it
                        app.ta_functions.sendemail_changeally( "Change Ally",
                            "support@changeally.com",
                            "Duplicate user",
                            "Someone just tried to sign up with a similar email. " + email );
                        res.redirect('/thankyou');
                    }
                });
            }
        });
    });

    var userapi = require(__dirname + '/server/api/users')(app);
    app.get('/api/login_as/:userId', function( req, res, next ) {
        function sudoto ( err, o )
        {
            if ( err || o === null ) return res.send( 404, "User not found" );

            var original_user = req.user;
            var original_user_id = req.user._id.toString();
            var original_username = req.user.prettyLogging();

            passport.authenticate('ta_signin_as', { user_to_become: o })(req, res, function () {
                /* sudo to yourself */
                if ( req.session.sudoer == req.user._id.toString() )
                {
                    req.session.sudoer = undefined;
                    req.session.sudoer_username = undefined;
                }
                /* sudo from yourself to user A user */
                else if ( !req.session.sudoer )
                {
                    req.session.sudoer = original_user_id;
                    req.session.sudoer_username = original_username;
                }
                /* else sudo from user A to user B, leave the sudoer info as is */

                log( ("Sudoing from:" + original_user_id + " " + original_user.prettyLogging()).red );
                log( ("Sudoing to  :" + req.user.id  + " " + req.user.prettyLogging()).red );
                res.send(200);
            });

        }
        if ( req.user._id.toString() == req.params.userId)
        {
            console.log( "You cannot sudo login_as your self." );
            return res.send(401, "You cannot sudo login_as your self.");
        }
        if (req.user.isMultiTenantAdminP())
        {
            //return app.db.models.User.find_user_by_netid( req.params.userId, sudoto );
            return app.db.models.User.findById( req.params.userId, sudoto );
        }
        else if (req.user.isAdminP())
        {
            return app.db.models.User.findById( req.params.userId, function ( err, sudoee_user ) {
                if ( req.user.isMemberOfOrg( sudoee_user.organization.toString() ) )
                    sudoto( null, sudoee_user);
                else {
                    var msg = "suto user " + req.user.prettyLogging() + " is not a administrator of users org";
                    console.log( msg );
                    return res.send(401, msg );
                }
            });
        }
        else if (req.user.isTherapistP())
        {
            return userapi.has_client( req.user, req.params.userId, sudoto );
        }
        else
        {
            console.log( "suto user" + req.user.prettyLogging() + " is not a administrator/therapist" );
            return res.send(401, "User" + req.user.prettyLogging() + " is not a administrator/therapist");
        }
    });

    /**
     * load rest api implementation
     */
    app.resource('rest/therapists', require(__dirname + '/server/rest/therapists'));
    app.resource('reminders', require(__dirname + '/server/rest/reminders'));

    _.each([ 'admin', 'assignments', 'content_comment', 'email',
        'feedback', 'organizations', 'stats', 'tasks', 'therapists', 'users-http',
        'conversations'
    ], function (x) { require(__dirname + '/server/api/' + x )( app ); } );

    /**
     * Set view folders and template language
     */

    app.set('views', __dirname + '/');
    app.set('view engine', 'html');
    app.engine('html', engines.underscore);

    var exec = require('child_process').exec;
    function execute(command, callback){
        exec(command, function(error, stdout, stderr){ callback(stdout); });
    }

    /**
     * Routes
     */
    app.get('/new', function(req, res){
        res.render('app/tpl/landing',{});
    });

    app.get('/signup/:userid/:hash', app.db.models.User.valid_random_token( function ( req, res, valid, user ) {
        if ( valid )
            passport.authenticate('ta_signin_as', { user_to_become: user })(req, res, function () { res.redirect('/#signup'); });
        else
            res.send(401, "Invalid credentials"); //#FIXME needs pretty error message about being out of date;
    }));

    function render_start_index_page( path, req, res )
    {
        // execute("git show -s --format=%ci", function ( date ) {
        //   execute("git log --pretty=format:'%h' -n 1" /*"git rev-parse HEAD"*/, function ( commit ) {
        //     execute("git log -1 --pretty=%B", function ( message ) {
        //       execute("git log -1 --pretty=\"%aN %aE\"", function ( author ) {
        var settings = {
            commit_date: "".trim(),
            commit_message: "".trim(),
            commit_hash: "".trim(),
            commit_author: "".trim(),
            brand_color: function() {
                if ( app.ta_config.test ) { return "#ffff00"; }
                else if ( app.ta_config.test_therapyally_com ) { return "#40e0d0"; }
                else if ( app.ta_config.devel ) { return "#5bc85c"; }
                else { return "#428bca"; } /* production */
            }(),
            run_mode: function () {
                if ( config.prod ) return 'prod';
                else if ( config.devel ) return 'devel';
                else return 'test';
            }(),
            formbuilder: app.ta_config.formbuilder,
        };
        res.render( path, _.defaults( { settings: JSON.stringify( settings ) }, settings ) );
        //       });
        //     });
        //   });
        // });
    }

    app.get('/', function(req, res){
        console.log(req.hostname);
        if(req.hostname == "changeally.com")
            render_start_index_page('appnew/tpl/pornography-landing/index', req, res)
        else
            render_start_index_page( 'appnew/tpl/index', req, res );
        /*var location = "";
         if ( req.query.location ) {
         location = "?location=" + encodeURIComponent(req.query.location);
         }
         res.render('appnew/tpl/landing',{ location: location });*/
    });

    app.get('/newapp/', function(req, res){
        render_start_index_page( 'appnew/tpl/index', req, res );
    });
    app.get('/landing/', function(req, res){
        render_start_index_page('appnew/tpl/pornography-landing/index', req, res)
    });
    app.get('/thankyou/', function(req, res){
        render_start_index_page('appnew/tpl/pornography-landing/thankyou', req, res)
    });

    app.get('/v1/', function(req, res){
        render_start_index_page( 'app/tpl/index', req, res );
    });

    app.get('/login/byu', function (req, res, next) {
        if ( req.isAuthenticated()){ res.redirect('/#signup_info'); }
        else { byu_cas.login( req, res, next ); }
    });

    app.post('/login', function (req, res, next) {
        if ( req.isAuthenticated()){ res.redirect('/#signup_info'); }
        else { res.render('app/tpl/landing',{}); }
        //else { passport.authenticate('')ta_normal_strategy.login( req, res, next ); }
    });

    app.get('/auth', function (req, res, next) {
        var location = "";
        if ( req.query.location ) {
            location = "?location=" + encodeURIComponent(req.query.location);
        }
        res.render('appnew/tpl/landing',{ location: location });
    });

    app.get('/auth/byu-login', function (req, res, next) { byu_cas.login( req, res, next ); } );
    function handle_preload_fragment( req, res, next) {
        var location = "";
        if ( req.query.location ) {
            location = req.query.location;
        }
        res.redirect(302,  "/" + location);
    }
    app.get('/auth/byu-cas',
        passport.authenticate('byu-cas',
            { failureRedirect: '/', failureFlash: true /*, successRedirect: '/' */ }), handle_preload_fragment);

    app.post('/auth/normal', passport.authenticate('ta_normal', { auth_challenge: true, failureRedirect: '/', failureFlash: true /*, successRedirect: '/' */ }), handle_preload_fragment );

    app.post('/auth/phoneapp', passport.authenticate('ta_normal', { auth_challenge: true, failureFlash: 'incorrect password' /*, successRedirect: '/' */ }), function( req, res, next ){ res.send(200); } );

    app.post('/auth/logout', function (req, res, next){
        req.logout();
        res.send(200);
    });

    app.get('/logout', function (req, res, next) {

        var location = "";
        if ( req.query.location ) {
            location = req.query.location;
        }

        var BAD = req.session.BAD;
        req.logout();
        if ( req.session.CAS ) {
            //console.log("Redirecting to BYU Logout");
            byu_cas.logout( req, res, next );
        }
        else {
            res.render('appnew/tpl/landing',{location: location});
        }
    });

    app.get('/api/getlongtermauthtoken', function(req, res, next) {
        console.log( "req.session", req.session );
        console.log( "req.user", req.user );
        var cookie = require('cookie');
        var cookieParser = require('cookie-parser');
        if (req.headers.cookie) {
            reqcookie = cookie.parse(req.headers.cookie);
            reqsessionID = cookieParser.signedCookies( reqcookie, app.ta_config.session_secret )[ 'connect.sid' ];
            if ( reqsessionID ) {
                //console.log("HERE3");
                app.ta_config.session_store.get( reqsessionID, function ( err, session ) {
                    if ( err ) {
                        console.log( err, session ); return next( new Error( err ) );
                    }
                    console.log( "Found the sessionid " + reqsessionID );
                    res.send( { id: reqsessionID } );
                });
            }
            else
            {
                console.log( err, session ); return next( new Error( "BAD1" ) );
            }
        }
        else
        {
            console.log( err, session ); return next( new Error( "BAD2" ) );
        }
    });

    // Copied from above so that we don't break current apps, ideally use only this post in the future.
    app.post('/api/getlongtermauthtoken', function(req, res, next) {
        console.log( "req.session", req.session );
        console.log( "req.user", req.user );
        var cookie = require('cookie');
        var cookieParser = require('cookie-parser');
        if (req.headers.cookie) {
            reqcookie = cookie.parse(req.headers.cookie);
            reqsessionID = cookieParser.signedCookies( reqcookie, app.ta_config.session_secret )[ 'connect.sid' ];
            if ( reqsessionID ) {
                //console.log("HERE3");
                app.ta_config.session_store.get( reqsessionID, function ( err, session ) {
                    if ( err ) {
                        console.log( err, session ); return next( new Error( err ) );
                    }
                    console.log( "Found the sessionid " + reqsessionID );
                    res.send( { id: reqsessionID } );
                });
            }
            else
            {
                console.log( err, session ); return next( new Error( "BAD1" ) );
            }
        }
        else
        {
            console.log( err, session ); return next( new Error( "BAD2" ) );
        }
    });

    app.get('/auth/token/:id', function(req, res, next) {
        if ( req.params.id && session) {
            app.ta_config.session_store.get( req.params.id, function ( err, session ) {
                if ( err ) {
                    console.log( err, session ); return next( new Error( err ) );
                }
                if(session){
                    console.log( "session.passport.user", session.passport.user );
                    passport.authenticate('ta_signin_as', { user_to_become: { _id: session.passport.user, prettyLogging: function () {} }  })(req, res, function () {
                        res.status(200).end()
                    });
                }
            });
        }
    });
    app.post('/api/register/device', function( req, res ) {
        var emails = ['ei@ei.com','test@test1.com','ryanseamons@gmail.com','kyletew@gmail.com','kyle.tew@gmail.com',
            'paul.r.tew@gmail.com','paul...r...tew@gmail.com','c@c.com','ryan@therapyally.com','changeally99@yahoo.com',
            'paul...rtew@gmail.com','b@test.com','badchoice60@test.com','koen@gorgabal.nl','snax01million@test.com',
            'carlossthedwarf@test.com','dorian4sibyl@test.com'];
        app.db.models.User.findById( req.body.user_id, function ( err, user ) {
            if( err ){
                return res.send(501, "Device Registration Error" );
            } else {
                if(req.body.platform != null && typeof(user.devices) != 'undefined' && emails.indexOf(user.email) == -1){
                    if(user.devices.length > 0){
                        if(req.body.platform == 'android') {
                            user.find_device(req.body.deviceId, function (result) {
                                if (result) {
                                    app.db.models.User.update_device(req.body.user_id, req.body.deviceId, req.body.token, function (err, result) {
                                        if (err != null) {
                                            console.log('Token Update Failed');
                                            return res.send(501, "Device Registration Error")
                                        }
                                        return res.send(200, "Device Registration Successful");
                                    });
                                }
                                else {
                                    user.add_device({
                                        'platform': req.body.platform,
                                        'token': req.body.token,
                                        'deviceid': req.body.deviceId
                                    });
                                    return res.send(200, "Device Registration Successful");
                                }
                            });
                        }
                        else if(req.body.platform == 'ios'){
                            user.find_device_type(req.body.platform, function (result) {
                                if (result) {
                                    app.db.models.User.update_device_ios(req.body.user_id, req.body.platform, req.body.token, function (err, result) {
                                        if (err != null) {
                                            console.log('Token Update Failed');
                                            return res.send(501, "Device Registration Error")
                                        }
                                        return res.send(200, "Device Registration Successful");
                                    });
                                }
                                else {
                                    user.add_device( {'platform':req.body.platform,'token':req.body.token,'deviceid':req.body.deviceId});
                                    return res.send(200, "Device Registration Successful" );         }
                            });
                        }
                    }
                    else{
                        user.add_device( {'platform':req.body.platform,'token':req.body.token,'deviceid':req.body.deviceId});
                        return res.send(200, "Device Registration Successful" );
                    }
                }
            }
        });
    });
    app.get('*', function(req,res){
        console.log( "No route found for " + req.url );
        res.send(404, "No route found for " + req.url);
    });


    var connect = require('connect');
    app.ta_config.conn = {};
    function add_conn( id, conn ) {
        if ( id in app.ta_config.conn ) {
            app.ta_config.conn[id].push( conn );
        }
        else
            app.ta_config.conn[id] = [ conn ];
    }
    function remove_socket_conn( id, conn ) {
        if ( id in app.ta_config.conn ) {
            app.ta_config.conn[id] = _.filter( app.ta_config.conn[id], function (x) { return x !== conn; });
        }
    }
    app.ta_dispatch = function( id, emit_type, data) {
        //console.log('*********ID************'.green,id);
        //console.log('*********ObjectData ID************'.green,app.ta_config.conn);
        if ( id in app.ta_config.conn) {
            console.log( "Received message dispatch: FOUND " + id  );
            _.each( app.ta_config.conn[id], function (x) {
                x.emit(emit_type, data);
            });
        }
    };


    app.setup_io = function ( io ){
        io.use( function( socket, next ) {
            var cookie = require('cookie');
            var cookieParser = require('cookie-parser');
            var handshakeData = socket.request;
            if (handshakeData.headers.cookie) {
                handshakeData.cookie = cookie.parse(handshakeData.headers.cookie);
                //handshakeData.sessionID = connect.utils.parseSignedCookie(handshakeData.cookie['connect.sid'], app.ta_config.session_secret );
                handshakeData.sessionID = cookieParser.signedCookies( handshakeData.cookie, app.ta_config.session_secret )[ 'connect.sid' ];
                if ( handshakeData.sessionID ) {
                    //console.log("HERE3");
                    app.ta_config.session_store.get( handshakeData.sessionID, function ( err, session ) {
                        if ( err ) {
                            console.log( err, session );
                            return next( new Error( err ) );
                        }
                        if(session && session.passport){
                            handshakeData.session = session;
                            handshakeData.user = session.passport.user;
                            console.log( "Accepted socket.io connection from " + handshakeData.sessionID + " " + session.passport.user );
                        }
                        return next( );
                    });
                    //  return accept('Cookie is invalid.', false);
                }
                else {
                    return next( new Error( "Cookie is invalid." ) );
                }

            } else {
                return next( new Error( "No cookie transmitted." ) );
            }
        });
        io.sockets.on('connection', function (socket) {
            add_conn( socket.request.user, socket );
            socket.on('disconnect', function(){
                remove_socket_conn( socket.request.user, socket );
                console.log('socket.io user disconnected '+ socket.request.user );
            });
            socket.on('therapist_peer', function ( data ) {
                console.log('server therapist_peer', data );
            });
        });
    };
    return app;
}

function WhoopItAppConfig ( initial ) {
    return _.defaults( initial || {}, {
        isDevelOrTest: function () { return this.test || this.devel; },
        isDevel: function () { return this.devel; },
        isTest: function () { return this.test; }
    });
}

function startup ( initial_config )
{
    return startup_server( new WhoopItAppConfig( _.defaults( initial_config || {}, require(__dirname + '/config')) ) );
}

module.exports.devel = function ( c, cb ) {
    return startup( _.defaults( {
        dbname: 'whoopitapp',
        paramlogin: true,
        devel:true
    }, c ), cb );
};

module.exports.prod  = function ( c, cb ) { return startup( _.defaults( {
    dbname: 'whoopitapp',
    prod: true
}, c ), cb ); };
