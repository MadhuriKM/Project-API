const { StatusCode, StatusCodes } = require('http-status-codes')
const UserModel = require('../model/user')

// read alluser info except admin
const readAllUsers = async (req,res) => {
    try {
        res.json({ msg: "read all users"})
    } catch(err) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ status :false, msg: err.message})
    }
}

module.exports = { readAllUsers }

