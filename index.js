var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

// Note that the model is capitalized, but the individual object created in the POST route is lowercase
var User = require('./user-model'); // Don't need the .js extension

// Set up Passport strategy
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;

var strategy = new BasicStrategy(function(username, password, callback) {
    User.findOne({
        username: username
    }, function (err, user) {
        if (err) {  // Could not verify username
            callback(err);
            return;
        }

        if (!user) {    // Could verify username, and it's wrong
            return callback(null, false, {
                message: 'Incorrect username.'
            });
        }

        user.validatePassword(password, function(err, isValid) {
            if (err) {  // Could not validate password
                return callback(err);
            }

            if (!isValid) {
                // Could validate password, and it's wrong
                return callback(null, false, {
                    message: 'Incorrect password.'
                });
            }
            return callback(null, user);
        }); // end validatePassword()
        
    }); // end findOne()
});

passport.use(strategy);

var jsonParser = bodyParser.json();

var app = express();
app.use(passport.initialize()); // Integrate Passport with the Express app

// Create a POST route
app.post('/users', jsonParser, function(req, res) {
    
    if (!req.body) {
        return res.status(400).json({
            message: "No request body"
        });
    }
    
    if (!('username' in req.body)) {
        return res.status(422).json({
            message: 'Missing field: username'
        });
    }
    
    var username = req.body.username;
    
    if (typeof username !== 'string') {
        return res.status(422).json({
            // Better error message than what is in the lesson
            message: 'Field "username" must be of type string'
        });
    }
    
    username = username.trim();
    
    if (username === '') {
        return res.status(422).json({
            message: 'Field "username" must be at least one character in length'
        });
    }
    
    if (!('password' in req.body)) {
        return res.status(422).json({
            message: 'Missing field: password'
        });
    }
    
    var password = req.body.password;
    
    if (typeof password !== 'string') {
        return res.status(422).json({
            message: 'Field "password" must be of type string'
        });
    }
    
    password = password.trim();
    
    if (password === '') {
        return res.status(422).json({
            message: 'Incorrect field length: password'
        });
    }
    
    // 10 is how many rounds of salting algorithm should be used. 
    // 10-12 is a good balance between security benefits and performance losses.
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return res.status(500).json({
                message: 'Internal server error'
            });
        }
        
        bcrypt.hash(password, salt, function(err, hash) {
            if (err) {
                return res.status(500).json({
                    message: 'Internal server error'
                });
            }
            
            var user = new User({
                username: username,
                password: hash
            });

            user.save(function(err) {
                if (err) {
                    return res.status(500).json({
                        message: 'Internal server error'
                    });
                }

                return res.status(201).json({});
            });
        }); // end hash()
    }); // end genSalt
    
});

// authenticate() call indicates we want BA and don't want to store a session cookie to keep identifying the user
// will need to re-auth with every new API request
app.get('/hidden', passport.authenticate('basic', {session: false}), function(req, res) {
    console.log('A GET request was made to "/hidden"');
    console.log('Req: ', req);
    var greeting = 'Luke, I am your father';
    console.log(greeting);
    res.json({
        message: greeting
    });
});

// Use promise instead of callback
mongoose.connect('mongodb://localhost/auth').then(function() {
    app.listen(process.env.PORT || 8080);
});