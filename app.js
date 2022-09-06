var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

require('dotenv').config({path: './.env'});

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// setup passport
app.use(session({
  secret: 'CanYouLookTheOtherWay',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// environment variables
const OKTA_BASE_URL = process.env.OKTA_BASE_URL;
console.log('OKTA_BASE_URL: ', OKTA_BASE_URL);

// set up passport
passport.use('oidc', new Strategy({
  issuer: `${OKTA_BASE_URL}/oauth2/default`,
  authorizationURL: `${OKTA_BASE_URL}/oauth2/default/v1/authorize`,
  tokenURL: `${OKTA_BASE_URL}/oauth2/default/v1/token`,
  userInfoURL: `${OKTA_BASE_URL}/oauth2/default/v1/userinfo`,
  clientID: `${process.env.OKTA_CLIENT_ID}`,
  clientSecret: `${process.env.OKTA_CLIENT_SECRET}`,
  callbackURL: `${process.env.OKTA_CALLBACK_URI}`,
  scope: 'openid profile',
}, (issuer, profile, done) => {
  return done(null, profile);
}));


passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

// set up routes

app.use('/', indexRouter);
app.use('/users', usersRouter);

// Redirect to the sign-in page
app.use('/login', passport.authenticate('oidc'));

app.use('/api/auth/callback/okta',
  passport.authenticate('oidc', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/profile');
  }
);

app.post('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

app.use('/profile', (req, res) => {
  res.render('profile', { user: req.user });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
