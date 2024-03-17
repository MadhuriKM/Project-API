const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    mobile:{
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    password:{
        type: String,
        required: true,
        trim: true
    },
    gender: {
        type: String,
        enum: ["male", "female","transgender"]
    },
    dob:{
        type: Date,
        default: new Date().toString()
    },
    role: {
        type: String,
        enum: ["user", "superadmin","agent"],
        default: "user"
    },
    qualification:[
        {
            type: String,
            default: "none"
        }
    ],
    address:[
        {
            type: Object,
            default: {}
        }
    ],
    isBlocked: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    }
},{
    collection: "users",
    timestamps: true
})

module.exports = mongoose.model("UserModel",UserSchema)