const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const Users = require('./users/users-model.js');

const protected = require('./auth/protected-middleware');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

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
