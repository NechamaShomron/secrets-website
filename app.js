
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.CONNECTION,{useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);
const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId:String,
  secrets: []
});

userSchema.plugin(passportLocalMongoose, {usernameUnique: false});
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done){
  done(null, user.id);
});
passport.deserializeUser(function(id, done){
  User.findById(id, function(err, user){
    done(err,user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id,  username: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id ,username: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
  res.render("home");
})
app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"]})
);
app.get("/auth/google/secrets",
  passport.authenticate('google', {failureRedirect: "/login"}),
  function(req,res){
    res.redirect("/secrets");
  })

  app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: 'public_profile'}));

  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      res.redirect('/secrets');
    });

  app.route("/register")
  .get(function(req,res){
  res.render("register");
})
.post(function(req,res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
    console.log(err);
    res.redirect("/register");
  }
    else{
      passport.authenticate("local")(req,res, function(){
        res.redirect("/secrets");
      })
    }
  })
});
app.route("/login")
  .get(function(req,res){
  res.render("login");
})
  .post(function(req,res){
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    req.login(user, function(err){
      if(err)
      console.log(err);
      else if(user){
      passport.authenticate("local")(req,res, function(){
        res.redirect("/secrets");
      })
    }
    else
    res.send("Incorrect email or password");
    })
  });
app.get("/secrets", function(req, res){
  if(req.isAuthenticated()){
    User.find({"secrets":{$ne:null}}, function(err, foundUsers){
      if(err)
      console.log(err);
      else if (foundUsers){
        const allSecrets = [];
        foundUsers.forEach(user =>{
          allSecrets.push(user.secrets);
        })
        //Concatenates arrays into one array
        allSecrets.forEach(secret =>{
            allSecrets.concat(secret);
          });
          //flattens multiple arrays in a single one
          const secretsArray = [].concat.apply([], allSecrets);
        res.render("secrets",{secretsArray: secretsArray});
      }
    })
}
  else
    res.redirect("/login");
})

app.route("/submit")
  .get(function(req,res){
    if(req.isAuthenticated()){
      res.render("submit");
  }
    else
      res.redirect("/login");
  })
  .post(function(req,res){
    const secret = req.body.secret;
    User.findById(req.user._id, function(err, foundUser){
      if(err)
      res.send(err);
      else{
        if(secret !== ""){
      foundUser.secrets.push(secret);
      foundUser.save();
      res.redirect("/secrets")
    }
    else
    res.redirect("/submit");
  }

    })
  });


app.get("/profile", function(req,res){
  if(req.isAuthenticated()){
    User.findById(req.user._id, function(err, foundUser){
      if(err)
      console.log(err);
      else{
        res.render("profile", {user: foundUser})
  }
})
}
else
  res.redirect("/login");
})

app.post("/delete", function(req,res){
  const itemToDelete = req.body.checkbox;
  User.findById(req.user._id, function(err, foundUser){
    if(err)
    console.log(err);
    else{
      foundUser.secrets.splice(itemToDelete, 1);
      foundUser.save();
      res.render("profile", {user:foundUser});
    }
})
})

app.get("/logout", function(req,res){
  req.logout();
  req.session.destroy(err => {
  if (!err) {
    res
      .status(200)
      .clearCookie("connect.sid", { path: "/" })
      .redirect("/");
  } else {
    console.log(err);
  }
});
});



app.listen(process.env.PORT || 3000, function(){
  console.log("Server started on port 3000");
})
