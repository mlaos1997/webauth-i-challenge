const bcrypt = require('bcryptjs');
const Users = require('../users/users-model.js');

function protected(req, res, next) {
    if (req.session && req.session.user) {
        next();
    } else {
        res
            .status(401)
            .json({message: 'Please provide credentials'})
    }
}

module.exports = protected;