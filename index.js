const express = require('express')
const dotenv = require('dotenv')
dotenv.config()
const cors = require('cors')
const cookieParser = require('cookie-parser')
const { StatusCodes } = require('http-status-codes')
const dbConnect = require('./db/connect')

const PORT = process.env.PORT

const app = express()

// middleware
app.use(express.urlencoded({ extended: true}))
app.use(express.json())
app.use(cors())
app.use(cookieParser(process.env.ACCESS_SECRET)) // secure cookies

// initial route
app.get(`/`, async (req,res) => {
    return res.status(StatusCodes.ACCEPTED).json({ status: true, msg: "Welcome to Project-API"})
})

// api routes
app.use(`/api/auth`, require('./route/authRoute'))

// default route
app.all(`/*`, async (req,res) => {
    return res.status(StatusCodes.ACCEPTED).json({ status: true, msg: "Requested path not found"})
})

app.listen(PORT, ()=> {
    dbConnect()
    console.log(`server is started @ http://localhost:${PORT}`)
})
