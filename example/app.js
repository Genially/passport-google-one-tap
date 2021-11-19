var dotenv = require("dotenv-flow");

dotenv.config();

var createError = require("http-errors");
var express = require("express");
var passport = require("passport");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
var cookieSession = require("cookie-session");

var indexRouter = require("./routes/index");
var authRouter = require("./routes/auth");

var app = express();
app.set("trust proxy", 1);

app.use(
  cookieSession({
    name: "session",
    keys: ["super secret"],
  })
);

require("./boot")();
require("./auth")();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// session setup
//
// This sequence of middleware is necessary for login sessions.  The first
// middleware loads session data and makes it available at `req.session`.  The
// next lines initialize Passport and authenticate the request based on session
// data.  If session data contains a logged in user, the user is set at
// `req.user`.
app.use(
  require("express-session")({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use("/", indexRouter);
app.use("/", authRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

module.exports = app;
