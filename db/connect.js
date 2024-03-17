const mongoose = require('mongoose')

const dbConnect = async () => {
    // local db -> mode is development
    if(process.env.MODE=== "development") {
        await mongoose.connect(process.env.MONGO_DEV)
        .then(res => {
            console.log(`local mongodb connected`)
        }).catch(err=> console.log(err.message))
    }

    // cloud db => mode is production
    if(process.env.MODE=== "production") {
        await mongoose.connect(process.env.MONGO_DEV)
        .then(res => {
            console.log(`local mongodb connected`)
        }).catch(err=> console.log(err.message))
    }

}
module.exports = dbConnect