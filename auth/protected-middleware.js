const bcrypt = require('bcryptjs');
const Users = require('../users/users-model.js');


function protected(req, res, next) {
    const {username, password} = req.headers;

    if (username && password) {
        Users
            .findBy({username})
            .first()
            .then(user => {
                // password is guess, user.password is the password in the database
                if (user && bcrypt.compareSync(password, user.password)) {
                    next();
                } else {
                    res
                        .status(401)
                        .json({message: 'Invalid Credentials'});
                }
            })
            .catch(error => {
                res
                    .status(500)
                    .json(error);
            });
    } else {
        res
            .status(400)
            .json({message: 'Please provide credentials'})
    }
}

module.exports = protected;