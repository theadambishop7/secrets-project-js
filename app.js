import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import morgan from 'morgan';
import dotenv from 'dotenv';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import session from 'express-session';
import flash from 'connect-flash';
import GoogleStrategy from 'passport-google-oauth20';
import findOrCreate from 'mongoose-findorcreate';

// Constants
const saltRounds = 10;
const port = 3000;
const app = express();
const uri = dotenv.config().parsed.DATABASE_URL;


// Middleware
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('short'));
app.use(session({
    secret: dotenv.config().parsed.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(flash());   // Flash error message
app.use(passport.initialize());
app.use(passport.session());


// Database configuration
mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
    googleId: String,
    username: String,
    authMethod: String,
    password: String
});

const secretSchema = new mongoose.Schema({
    secret: String
});

// Plugins and model setup
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model('User', userSchema);
const Secret = mongoose.model('Secret', secretSchema);

// Passport configuration
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Google OAuth
passport.use(new GoogleStrategy({
    clientID: dotenv.config().parsed.CLIENT_ID,
    clientSecret: dotenv.config().parsed.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    const email = profile.emails[0].value;
    User.findOrCreate({ googleId: profile.id }, {username: email, authMethod: "OAuth"}, function (err, user) {
      return cb(err, user);
    });
  }
));



// Routes
app.get('/', (req, res) => {
    if (req.query.logged_out === 'true') {
        res.render('home.ejs', { messages: 'Successfully logged out.' });
    } else {
        res.render('home.ejs');
    }
});

app.route('/register')
.get((req, res) => {
    res.render('register.ejs', { messages: req.flash('error') });
})
.post((req, res) => {
    User.register({username: req.body.username, authMethod: "email"}, req.body.password, (err, user) => {
        if (err) {
            if (err.name === 'UserExistsError') {
                req.flash('error', 'A user with the given email is already registered. Try to <a href="/login">login</a> instead.');
            } else {
                req.flash('error', 'An unexpected error occurred. Please try again.');
            }
            return res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/secrets');
    });




app.route('/login')
.get((req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/secrets');
    } else {
        res.render('login.ejs', { messages: req.flash('error') });
    }
})
.post ((req, res, next) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            console.log(err);
            req.flash('error', 'An unexpected error occurred. Please try again.');
            res.redirect('/login');
        } else {
            passport.authenticate('local', {
                successRedirect: '/secrets',
                failureRedirect: '/login',
                failureFlash: 'Invalid username or password.' // Flash error message
            })(req, res, next);
        }
    });
});


app.route('/secrets')
.get((req, res) => {
    if (req.isAuthenticated()) {
        Secret.find({}).then((secrets, err) => {
            if (err) {
                res.render('secrets.ejs', { secrets: [] })
            } else {
                res.render('secrets.ejs', { secrets: secrets });
            }
        });
    } else {
        req.flash('error', 'You must be logged in to view this page.');
        res.redirect('/login');
    }
});

app.route("/submit")
.get((req, res) => {
    if (req.isAuthenticated()) {
        res.render('submit.ejs');
    } else {
        req.flash('error', 'You must be logged in to view this page.');
        res.redirect('/login');
    }
})
.post((req, res) => {
    const secret = new Secret({
        secret: req.body.secret
    });
    secret.save().then(() => {
            res.redirect('/secrets');
        })
    .catch((err) => {
        console.log(err);
        res.redirect('/submit');
    })
});


app.route('/logout')
.get((req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
    });
    res.redirect('/?logged_out=true');
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});


