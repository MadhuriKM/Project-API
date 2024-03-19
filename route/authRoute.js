const route = require('express').Router()
const { register, login,logout, verifyUser } = require('../controller/authCtrl')
const auth = require('../middleware/auth')

route.post(`/register`, register)

route.post(`/login`, login)

route.get(`/logout`,logout)

route.get(`/verify/user`,auth, verifyUser)

module.exports = route