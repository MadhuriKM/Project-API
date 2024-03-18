const jwt = require('jsonwebtoken')

// json token
const generateToken = (id) => {
    return jwt.sign({id},process.env.ACCESS_SECRET,{ expiresIn: '1d'})
}

module.exports = generateToken