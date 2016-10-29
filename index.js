var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

// Note that the model is capitalized, but the individual object created in the POST route is lowercase
var User = require('./user-model'); // Don't need the .js extension

var jsonParser = bodyParser.json();

var app = express();

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

// Use promise instead of callback
mongoose.connect('mongodb://localhost/auth').then(function() {
    app.listen(process.env.PORT || 8080);
});