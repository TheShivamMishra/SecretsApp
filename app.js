//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    // some intital passport configuration.
    secret: "any long string.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize()); // intializing passport for using it for authentication.
app.use(passport.session()); // using passport for session managment.

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
});
mongoose.set("useCreateIndex", true); // to dissable deprecated warning.

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose); //using passport local mongoose for hasing and salting of username and password;
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/submit", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (!err)
      res.render("submit", {
        arr: foundUsers,
      });
    else console.log(err);
  });
});

app.get("/secrets", function (req, res) {
  User.find({}, function (err, results) {
    if (err) console.log(err);
    else
      res.render("secrets", {
        itemArr: results,
      });
  });
});

app.post("/register", function (req, res) {
  User.register({ username: req.body.username }, req.body.password, function (
    err,
    user
  ) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        //making authentication of the user using cookie;
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) console.log(err);
    else {
      passport.authenticate("local")(req, res, function () {
        //making authentication of the user using cookie;
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", function (req, res) {
  // console.log(req.user);
  User.findById(req.user._id, function (err, foundUser) {
    if (err) console.log(err);
    else {
      foundUser.secret += req.body.secret + "\n";
      foundUser.save(function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("Server is Running on Port: 3000");
});
