const nodemailer = require('nodemailer')

const mailsend = async (receiver,sub,template,fileAttachment) => {
    try {
        // config for nodemailer
        const transporter = await nodemailer.createTransport({
            service:process.env.MAIL_SERVICE,
            port: process.env.MAIL_PORT,
            host: process.env.MAIL_HOST,
            auth: {
                user: process.env.MAIL_USER,
                pass: process.env.MAIL_PASS
            }
        })

        // email sender
        let res = await transporter.sendMail({
            from: process.env.MAIL_USER,
            to: receiver,
            subject: sub,
            html: `<div> ${template} </div>`,
            attachments: fileAttachment
        })
         return res
    } catch (err) {
        return err.message
    }
}

module.exports = mailsend