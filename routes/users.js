var express = require('express');
var router = express.Router();
var flash = require('connect-flash');
var speakeasy = require('speakeasy');
var notp = require('notp');
var base32 = require('thirty-two');
var crypto = require('crypto');

var dbConfig = require('../db.js');
var mongoose = require('mongoose');
mongoose.connect(dbConfig.url);

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var bcrypt = require('bcryptjs');

var mongoose = require('mongoose');
var User = mongoose.model('User',{
    username: String,
    password: String,
    email: String,
    firstName: String,
    lastName: String,
    gender: String,
    address: String,
    key: String
});

passport.serializeUser(function(user, done) {
  done(null, user._id);
});
 
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Generates hash using bCrypt
var createHash = function(password){
 return bcrypt.hashSync(password, bcrypt.genSaltSync(10), null);
}

passport.use('signup', new LocalStrategy({
    passReqToCallback : true
  },
  function(req, username, password, done) {
    findOrCreateUser = function(){
      var usernameRegex = /^[a-zA-Z0-9]+$/;
      if (!username.match(usernameRegex)) {
        console.log('Not valid username');
        req.session.error = 'Not valid username. Only alphanumeric letter are valid.';
        return done(null, false, req.flash('message','Not valid username. Only alphanumeric letter are valid.'));
      };

      // find a user in Mongo with provided username
      User.findOne({'username':username},function(err, user) {
        // In case of any error return
        if (err){
          console.log('Error in SignUp: '+err);
          return done(err);
        }
        // already exists
        if (user) {
          console.log('User already exists');
          return done(null, false, 
             req.flash('message','User Already Exists'));
        } else {
          // if there is no user with that email
          // create the user
          var newUser = new User();
          // set the user's local credentials
          newUser.username = username;
          newUser.password = createHash(password);
          newUser.email = req.param('email');
          newUser.firstName = req.param('firstName');
          newUser.lastName = req.param('lastName');
 
          // save the user
          newUser.save(function(err) {
            if (err){
              console.log('Error in Saving user: '+err);  
              throw err;  
            }
            console.log('User Registration succesful');    
            return done(null, newUser);
          });
        }
      });
    };
     
    // Delay the execution of findOrCreateUser and execute 
    // the method in the next tick of the event loop
    process.nextTick(findOrCreateUser);
  })
);

var isValidPassword = function(user, password){
  return bcrypt.compareSync(password, user.password);
}

passport.use('login', new LocalStrategy({
    passReqToCallback : true
  },
  function(req, username, password, done) { 
    // check in mongo if a user with username exists or not
    User.findOne({ $or:[ {'username' :  username }, {'email' :  username }]}, 
      function(err, user) {
        // In case of any error, return using the done method
        if (err)
          return done(err);
        // Username does not exist, log error & redirect back
        if (!user){
          console.log('User Not Found with username '+username);
          return done(null, false, 
                req.flash('message', 'User Not found.'));                 
        }
        // User exists but wrong password, log the error 
        if (!isValidPassword(user, password)){
          console.log('Invalid Password');
          return done(null, false, 
              req.flash('message', 'Invalid Password'));
        }
        // User and password both match, return user from 
        // done method which will be treated like success
        return done(null, user);
      }
    );
}));

var isAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) return next();
  delete req.session.user;
  delete req.session.key;
  res.redirect('/users/sign_in');
}

/* GET login page. */
router.get('/sign_in', function(req, res, next) {
  if (req.isAuthenticated()) return res.redirect('/');
  delete req.session.key;
  res.render('sign_in', { title: 'Express', message: req.flash('message'), title: 'Sign In | 2-step Authentication'});
});
 
/* Handle Login POST */
router.post('/sign_in', function(req, res, next) {
  passport.authenticate('login', function(err, user, info) {
    if (err) { return next(err); }
    if (!user) { 
      req.session.error = 'Invalid email or password'
      return res.redirect('/users/sign_in');
    }

    if (user && user.key) {
      req.session.user = user;
      return res.redirect('/users/two-factor');
    };

    req.logIn(user, function(err) {
      if (err) { return next(err); }
      return res.redirect('/');
    });
  })(req, res, next);
});
 
/* GET Registration Page */
router.get('/sign_up', function(req, res, next) {
  if (req.isAuthenticated()) return res.redirect('/');
  res.render('sign_up', { title: 'Express', message: req.flash('message'), title: 'Sign Up | 2-step Authentication'});
});

 
/* Handle Registration POST */
router.post('/sign_up', passport.authenticate('signup', {
  successRedirect: '/index',
  failureRedirect: '/users/sign_up',
  failureFlash : true 
}));

/* Handle Logout */
router.get('/sign_out', function(req, res) {
  req.logout();
  res.redirect('/');
});

router.get('/two-factor', function(req, res, next) {
  if (!req.session.user) { return res.redirect('/users/sign_in'); };
  res.render('two_factor', { user: req.user, title: 'Two Factor | 2-step Authentication'});
});

router.post('/two-factor', function(req, res, next) {
  if (!req.session.user) { return res.redirect('/users/sign_in'); };
  var isValidToken = notp.totp.verify(req.body.token, req.session.user.key);
  if (!isValidToken) {
    req.session.error = "Invalid Token";
    return res.redirect('/users/two-factor');
  };

  req.logIn(req.session.user, function(err) {
    if (err) { return next(err); }
    delete req.session.user;
    return res.redirect('/');
  });
});

function s4() {
  return Math.floor(Math.random() * 10000);
}

function randomNumber() {
  return "random" + (s4() + s4() + s4() + s4())* (new Date()).getTime();
}

router.get('/two-factor-setup', isAuthenticated, function(req, res, next) {
  // encoded will be the secret key, base32 encoded
  if (!req.session.key) {
    req.session.key = crypto.createHash('md5').update(randomNumber()).digest('hex');
    var encoded = base32.encode(req.session.key);

    // Google authenticator doesn't like equal signs
    req.session.encodedForGoogle = encoded.toString().replace(/=/g,'');
  };
  
  // to create a URI for a qr code (change totp to hotp if using hotp)
  var uri = 'otpauth://totp/'+req.user.username+'?secret=' + req.session.encodedForGoogle;
  res.render('two_factor_setup', { user: req.user, title: 'Express', uri: uri, secret_key: req.session.key });
});

router.post('/two-factor-setup', isAuthenticated, function(req, res, next) {
  var key = req.session.key;
  var token = req.body.token;
  var isValidToken = notp.totp.verify(token, key);
  if (!isValidToken) {
    req.session.error = "Invalid Token";
    return res.redirect('/users/two-factor-setup');
  };

  User.findOne({ 'username' :  req.user.username }, 
    function(err, user) {
      // In case of any error, return using the done method
      if (err)
        return done(err);
           
      user.key = req.session.key;
      user.save(function(err) {
        if (err){
          console.log('Error in Activating: '+err);  
          return res.redirect('/users/two-factor-setup');
        }
        console.log('Two Factor Activated ');    
        res.redirect('/users/two-factor-activated');
      });
    }
  );   
});

router.get('/two-factor-activated', isAuthenticated, function(req, res, next) {
  delete req.session.key;
  res.render('two_factor_activated', { user: req.user, title: 'Express', message: req.flash('message') });
});

router.get('/two-factor-deactivate', isAuthenticated, function(req, res, next) {
  User.findOne({ 'username' :  req.user.username }, 
    function(err, user) {
      // In case of any error, return using the done method
      if (err)
        return done(err);
           
      user.key = "";
      user.save(function(err) {
        if (err){
          console.log('Error in Deactivating: '+err);
          req.session.error = "Unable to activate 2-step authentication.";  
          return res.redirect('/users/two-factor-setup'); 
        }
        console.log('User Two Factor De Activated ');  
        req.session.success = "You have succesfully activated 2-step authentication.";    
        res.redirect('/users/two-factor-setup'); 
      });
    }
  ); 
});

module.exports = router;
