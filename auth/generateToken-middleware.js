const jwt = require('jsonwebtoken');

function generateToken(user) {
    // return a call to sign method of json token
    const payload = {
        subject: user.id, // sub
        username: user.username,
        // ...other data
    }

    const secret = 'my secret shhh'
    const options = {
        expiresIn: '8h',
    }

    return jwt.sign(payload, secret, options);
}

module.exports = generateToken;