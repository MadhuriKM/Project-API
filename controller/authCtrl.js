const { StatusCodes } = require("http-status-codes")
const UserModel = require('../model/user')
const bcryptjs = require("bcryptjs")

// register
const register  = async(req,res) => {
    try {
        // read the data
        const {name, email, mobile, password,role} = req.body

        // check whether user email and mobile registered or not
        let extEmail = await UserModel.findOne({email})
            if(extEmail)
                return res.status(StatusCodes.CONFLICT).json({ status: false, msg: `${email} id already exist`})

        let extMobile = await UserModel.findOne({mobile})
            if(extMobile)
                return res.status(StatusCodes.CONFLICT).json({ status: false, msg: `${mobile} number already exists`})

        // password enncryption
        let encPass = await bcryptjs.hash(password,10)
        // salt => encrypted data (alpha numerical)

        // method to store in db
        let newUser = await UserModel.create({
            name,
            email,
            mobile,
            password: encPass,
            role
        })
        // final response
        res.status(StatusCodes.ACCEPTED).json({ status: true, msg: "User Registered successfully", user : newUser })
    } catch (err) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ status: false, msg: err.message})
    }
}

// login 
const login  = async(req,res) => {
    try {
        const { email, password } = req.body

        // to check email is exists or not
        let extEmail = await UserModel.findOne({email})
        if(!extEmail)
            return res.status(StatusCodes.NOT_FOUND).json({ status: false, msg: `${email} id doesn't exists`})

        // validate the password
        let passVal = await bcryptjs.compare(password,extEmail.password)
            if(!passVal)
                return res.status(StatusCodes.UNAUTHORIZED).json({ status: false, msg: `Password are not matched`})
       
        res.json({ msg: "login success"})
    } catch (err) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ status: false, msg: err.message})
    }
}

// logout
const logout  = async(req,res) => {
    try {
        res.json({ msg: "logout"})
    } catch (err) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ status: false, msg: err.message})
    }
}

// verify user
const verifyUser  = async(req,res) => {
    try {
        res.json({ msg: "verify user"})
    } catch (err) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ status: false, msg: err.message})
    }
}

module.exports = { register, login, logout, verifyUser}