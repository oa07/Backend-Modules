const mongoose = require('mongoose');

const AuthSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: [true, 'Please add a username'],
    min: 4
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    min: 6,
    max: 255,
    unique: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please add a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please add a password'],
    min: 6,
    max: 1024,
    select: false
  },
  phoneNumber: {
    type: String,
    unique: true,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'customer', 'worker'],
    required: true
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  verifyAccountToken: String,
  isAccountVerified: Boolean,
  isAccountActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now()
  }
});

module.exports.AuthModel = mongoose.model('user', AuthSchema);
