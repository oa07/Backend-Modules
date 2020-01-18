const nodemailer = require('nodemailer');
const { emailID, emailPassword, port } = require('../../config/config');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: emailID,
    pass: emailPassword
  }
});

module.exports.sendMailForgetPasswordToken = async (
  username,
  userEmail,
  token
) => {
  const link = `<CLIENT_URI>/${token}`;
  const mailOptions = {
    from: emailID,
    to: userEmail,
    subject: 'Generated Token For Reset Password',
    html: `
      <h1> Hi ${username}, </h1>
      <h2> Copy This token and paste it into POSTMAN </h2>
      <h4> ${link} </h4>
    `
  };

  return transporter.sendMail(mailOptions);
};

exports.sendMailVerifyAccount = async (username, userEmail, token) => {
  const link = `<CLIENT_URI>/${token}`;
  const mailOptions = {
    from: emailID,
    to: userEmail,
    subject: 'Generated Token For Verify Token',
    html: `
      <h1> Hi ${username}, </h1>
      <h2> Copy This token and paste it into POSTMAN </h2>
      <h4> ${link} </h4>
    `
  };

  return transporter.sendMail(mailOptions);
};
