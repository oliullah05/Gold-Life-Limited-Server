import nodemailer from 'nodemailer'
import config from '../config'
export const sendEmail = async (to: string, html: string) => {
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com.',
    port: 587,
    secure: config.NODE_ENV === 'production',
    auth: {
      // TODO: replace `user` and `pass` values from <https://forwardemail.net>
      user: config.nodemailer_email,
      pass: config.nodemailer_app_password
    }
  })

  await transporter.sendMail({
    from: config.nodemailer_email, // sender address
    to, // list of receivers
    subject: `Reset your password within ${config.reset_password_time} mins!`, // Subject line
    text: '', // plain text body
    html // html body
  })
}
