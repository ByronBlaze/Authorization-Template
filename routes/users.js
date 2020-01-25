const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

//user model
const User = require('../models/User');

//login page
router.get('/login', ( req, res) => res.render('login'));

//register page
router.get('/register', ( req, res) => res.render('register'));

// Register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    //Checking required fields
    if( !name || !email || !password || !password2) {
        errors.push({ msg: 'Please fill in all fields'});
    }

    //checking passwords
    if( password !== password2){
        errors.push({ msg: 'Passswords do not match'});
    }

    //check pass length
    if(password.length < 6) {
        errors.push({msg: 'Password should be atleast 6 character'});
    }

    //check pass equal to username or email
    if(password == name || password == email){
        errors.push({msg: 'Password cannot be your username or email.'});
    }

    if(errors.length > 0) {
        res.render('register', {
           errors,
           name,
           email,
           password,
           password2 
        });

    } else {
        User.findOne({ email : email})
            .then(user => {
                if(user){
                    //user exists
                    errors.push({ msg: 'Email is already registered'})
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2 
                     });
                } else {
                    const newUser = new User({
                        name, 
                        email,
                        password
                    });

                   // encryptying password hash
                   bcrypt.genSalt(10, (err, salt) => 
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;
                        //password to hash
                        newUser.password = hash;
                        //save user
                        newUser.save()
                            .then(user => {
                                req.flash('success_msg', 'You are now registered.');
                                res.redirect('/users/login')
                            })
                            .catch(err => console.log(err));
                   }))
                }
            });
    }
});

//Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

//Logout Handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('succes_msg', 'You are successfully logged out');
    res.redirect('/users/login');
});
module.exports = router;