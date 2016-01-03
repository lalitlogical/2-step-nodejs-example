var express = require('express');
var router = express.Router();

// As with any middleware it is quintessential to call next()
// if the user is authenticated
var isAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/users/sign_in');
}

/* GET home page. */
router.get('/', function(req, res, next) {
  delete req.session.user;
  delete req.session.key;
  res.render('index', { user: req.user });
});

router.get('/index', function(req, res, next) {
  delete req.session.user;
  delete req.session.key;
  res.render('index', { user: req.user });
});

module.exports = router;
