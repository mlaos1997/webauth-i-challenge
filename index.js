const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SessionStore = require('connect-session-knex')(session);

const Users = require('./users/users-model.js');

const protected = require('./auth/protected-middleware');

const server = express();

const sessionConfig = {
    name: 'monkey', // sid, we don't want others knowing we are using express-sessions
    secret: 'keep it secret, keep it safe',
    resave: false, // do we want to recreate session, even with no change
    saveUninitialized: false, // GDPR laws against setting cookies automatically, only true when user accepts, needs to change dynamically
    cookie: {
        maxAge: 60 * 60 * 1000, // cookie will be valid for an hour, then expire
        secure: process.env.NODE_ENV === 'production'
            ? true
            : false, // true in production
        httpOnly: true // cookie cannot be accessed with js
    },
    store: new SessionStore({
        knex: require('./data/dbConfig'),
        tablename: 'sessions',
        sidfieldname: 'sid',
        createTable: true,
        clearInterval: 60 * 60 * 1000
    }),
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
    res.send('<h2>WEB Auth I Challenge</h2>');
});

server.post('/api/register', (req, res) => {
    let user = req.body;
    // check for username and password

    const hash = bcrypt.hashSync(user.password, 12); // 2^12 rounds
    // password > hashit > hash > hashit > hash > hashit > hash hash the password
    user.password = hash;

    Users
        .add(user)
        .then(saved => {
            res
                .status(201)
                .json(saved);
        })
        .catch(error => {
            res
                .status(500)
                .json(error);
        });
});

server.post('/api/login', (req, res) => {
    let {username, password} = req.body;
    // we compare the password guess against the database hash
    Users
        .findBy({username})
        .first()
        .then(user => {
            // password is guess, user.password is the password in the database
            if (user && bcrypt.compareSync(password, user.password)) {
                req.session.user = user; // saving info about user on session, save and send cookie with user info
                res
                    .status(200)
                    .json({message: `Welcome ${user.username}!`});
            } else {
                res
                    .status(401)
                    .json({message: 'You Shall Not Pass...'});
            }
        })
        .catch(error => {
            res
                .status(500)
                .json(error);
        });
});

server.get('/api/logout', protected, (req, res) => {
    if (req.session) {
        req
            .session
            .destroy(err => {
                if (err) {
                    return res
                        .status(500)
                        .json({message: 'There was an error'})
                }
                res.end();
            });
    } else {
        res.end();
    }
});

// protect this route, users must provide valid credentials to see it
server.get('/api/users', protected, (req, res) => {
    Users
        .find()
        .then(users => {
            res.json(users);
        })
        .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
